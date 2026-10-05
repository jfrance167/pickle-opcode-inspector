"""Synthetic opcode cases, including errors; never restore serialized objects."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import pickle
import pickletools
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from opcode_inspector.core import MECHANISMS, inspect_bytes
from opcode_inspector.guard import BudgetError, Limits
from opcode_inspector.__main__ import main
from opcode_inspector.report import render
from tests.test_guard import CASES
from scripts.make_demo import create


class InspectorTests(unittest.TestCase):
    def test_demo_is_repeatable_and_preserves_other_evidence(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder)
            create(root)
            create(root)
            path = root / "hello.pkl"
            path.write_bytes(b"different evidence")
            with self.assertRaises(ValueError):
                create(root)
            self.assertEqual(path.read_bytes(), b"different evidence")

    def test_protocols_zero_through_five(self):
        for protocol in range(6):
            data = (b"\x80" + bytes([protocol]) if protocol else b"") + b"N."
            report = inspect_bytes(data)
            self.assertEqual(report["state"], "decoded")
            self.assertEqual(report["opcodes"][-1]["end"], len(data))

    def test_every_opcode_decodes_to_inert_record(self):
        # Some isolated opcodes lack a valid VM stack. Decoded does not mean
        # semantically valid; this tests operand coverage, not loadability.
        observed = set()
        for op in pickletools.opcodes:
            data = op.code.encode("latin-1")
            if op.arg:
                data += CASES[op.arg.reader.__name__]
            if op.name != "STOP":
                data += b"."
            with self.subTest(opcode=op.name):
                report = inspect_bytes(data)
                self.assertEqual(report["state"], "decoded")
                self.assertEqual(report["opcodes"][0]["name"], op.name)
                observed.add(op.name)
        self.assertTrue(set(MECHANISMS) <= observed)

    def test_names_are_not_imported_or_resolved(self):
        report = inspect_bytes(b"cno_such_lab_module\nno_such_symbol\n.")
        self.assertEqual(report["state"], "decoded")
        self.assertEqual(report["findings"][0]["opcode"], "GLOBAL")
        self.assertNotIn("no_such_lab_module", sys.modules)

    def test_restoration_apis_never_called(self):
        with patch.object(pickle, "load", side_effect=AssertionError), \
             patch.object(pickle, "loads", side_effect=AssertionError), \
             patch.object(pickle, "Unpickler", side_effect=AssertionError):
            self.assertEqual(inspect_bytes(b"N.")["state"], "decoded")
            self.assertEqual(inspect_bytes(b"cno_such_lab_module\nname\n.")["state"], "decoded")

    def test_stop_trailing_and_missing(self):
        for data in (b"", b"N", b"N.N.", b"N.\x00", b"\x00"):
            with self.subTest(data=data):
                self.assertEqual(inspect_bytes(data)["state"], "malformed")

    def test_offsets_are_exact(self):
        report = inspect_bytes(b"\x80\x05K\x07.")
        self.assertEqual([(o["offset"], o["end"]) for o in report["opcodes"]], [(0, 2), (2, 4), (4, 5)])

    def test_unsupported_protocol_and_runtime(self):
        self.assertEqual(inspect_bytes(b"\x80\x06N.")["state"], "unsupported")
        with patch("opcode_inspector.guard.REVIEWED_SOURCE", "changed"):
            report = inspect_bytes(b"N.")
        self.assertEqual(report["state"], "unsupported")
        self.assertEqual(report["opcodes"], [])

    def test_declared_body_and_numeric_limits(self):
        for data, limits in ((b"B" + struct.pack("<I", 9) + b"x" * 9 + b".", Limits(max_operand=8)),
                             (b"I" + b"1" * 1024 + b"\n.", Limits()),
                             (b"c" + b"x" * 9 + b"\nname\n.", Limits(max_operand=8))):
            with self.subTest(data=data[:8]):
                self.assertEqual(inspect_bytes(data, limits)["state"], "limit_exceeded")

    def test_numeric_line_boundary_and_global_second_line(self):
        report = inspect_bytes(b"I" + b"1" * 1023 + b"\n.")
        self.assertEqual(report["state"], "decoded")
        self.assertGreater(report["opcodes"][0]["argument"]["bits"], 3000)
        report = inspect_bytes(b"ca\n" + b"x" * 9 + b"\n.", Limits(max_operand=8))
        self.assertEqual(report["state"], "limit_exceeded")

    def test_regular_file_input_limit(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "synthetic.pkl"
            path.write_bytes(b"N.")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(path), "--max-bytes", "1"]), 2)

    def test_opcode_and_input_budgets(self):
        self.assertEqual(inspect_bytes(b"N.", Limits(max_opcodes=2))["state"], "decoded")
        self.assertEqual(inspect_bytes(b"N.", Limits(max_opcodes=1))["state"], "limit_exceeded")
        report = inspect_bytes(b"N.", Limits(max_bytes=1))
        self.assertEqual(report["state"], "limit_exceeded")
        self.assertNotIn("sha256", report)

    def test_large_binary_integer_has_no_decimal_conversion(self):
        report = inspect_bytes(b"\x8b" + struct.pack("<i", 4096) + b"\x7f" * 4096 + b".")
        arg = report["opcodes"][0]["argument"]
        self.assertEqual(report["state"], "decoded")
        self.assertGreater(arg["bits"], 30000)
        self.assertLess(len(render(report, "json")), 1024)

    def test_escaped_and_truncated_previews(self):
        data = b"B" + struct.pack("<I", 100) + bytes(range(100)) + b"."
        report = inspect_bytes(data)
        self.assertTrue(report["opcodes"][0]["argument"]["truncated"])
        report = inspect_bytes(b"V\\u001b[31m\n.")
        for format in ("text", "json"):
            output = render(report, format)
            output.encode("ascii")
            self.assertNotIn("\x1b", output)
            self.assertIn("\\u001b", output)

    def test_nonfinite_floats_and_invalid_unicode(self):
        for value in (float("inf"), float("nan")):
            report = inspect_bytes(b"G" + struct.pack(">d", value) + b".")
            json.loads(render(report, "json"))
        self.assertEqual(inspect_bytes(b"\x8c\x01\xff.")["state"], "malformed")

    def test_output_limit_and_exact_boundary(self):
        report = inspect_bytes(b"N" * 15 + b".")
        for format in ("text", "json"):
            full = render(report, format)
            self.assertEqual(render(report, format, len(full)), full)
            with self.assertRaises(BudgetError):
                render(report, format, len(full) - 1)
        for budget in (True, 1023, float("inf"), 5 * 1024 * 1024):
            with self.assertRaises(ValueError):
                render(report, max_output=budget)

    def test_random_small_malformed_inputs_are_controlled(self):
        rng = random.Random(20261005)
        for _ in range(1000):
            data = rng.randbytes(rng.randrange(0, 80))
            report = inspect_bytes(data, Limits(max_operand=128))
            self.assertIn(report["state"], {"decoded", "malformed", "unsupported", "limit_exceeded"})
            json.loads(render(report, "json"))

    def test_cli_states_io_and_invalid_budgets(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "synthetic.pkl"
            for data, expected in ((b"N.", 0), (b"cno_such_lab_module\nname\n.", 1), (b"N", 2)):
                path.write_bytes(data)
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(main([str(path), "--format", "json"]), expected)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(path), "--max-bytes", "0"]), 2)
                self.assertEqual(main([str(path.parent)]), 2)
                self.assertEqual(main([str(path) + ".missing"]), 2)

    def test_stdout_failures_return_two(self):
        for operation in ("write", "flush"):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with patch("sys.stdout." + operation, side_effect=BrokenPipeError), \
                     patch("opcode_inspector.__main__.read_input", return_value=b"N."):
                    self.assertEqual(main(["synthetic.pkl"]), 2)

    def test_closed_pipe_exits_cleanly(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=root / "tests") as folder:
            path = Path(folder) / "synthetic.pkl"
            path.write_bytes(b"N.")
            with subprocess.Popen([sys.executable, "-m", "opcode_inspector", str(path)], cwd=root,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                child.stdout.close()
                child.stdout = None
                try:
                    _, errors = child.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate()
                    self.fail("CLI did not terminate within timeout")
            self.assertEqual(child.returncode, 2)
            self.assertNotIn(b"Traceback", errors)
            self.assertNotIn(b"Exception ignored", errors)


if __name__ == "__main__":
    unittest.main()
