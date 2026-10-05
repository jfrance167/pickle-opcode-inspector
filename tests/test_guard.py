"""Direct reader witnesses: no unpickling or third-party fixtures."""

import pickletools
import struct
import unittest
from unittest.mock import patch

from opcode_inspector.guard import (
    BudgetError, GuardedStream, Limits, READERS, UnsupportedRuntime, verify_runtime,
)


CASES = {
    "read_bytearray8": struct.pack("<Q", 1) + b"a",
    "read_bytes1": b"\x01a", "read_bytes4": struct.pack("<I", 1) + b"a",
    "read_bytes8": struct.pack("<Q", 1) + b"a",
    "read_decimalnl_long": b"12L\n", "read_decimalnl_short": b"12\n",
    "read_float8": struct.pack(">d", 1.5), "read_floatnl": b"1.5\n",
    "read_int4": struct.pack("<i", -1), "read_long1": b"\x01\x01",
    "read_long4": struct.pack("<i", 1) + b"\x01",
    "read_string1": b"\x01a", "read_string4": struct.pack("<i", 1) + b"a",
    "read_stringnl": b"'a'\n", "read_stringnl_noescape": b"a\n",
    "read_stringnl_noescape_pair": b"a\nb\n", "read_uint1": b"\x01",
    "read_uint2": b"\x01\x00", "read_uint4": b"\x01\x00\x00\x00",
    "read_uint8": b"\x01" + b"\x00" * 7,
    "read_unicodestring1": b"\x01a", "read_unicodestring4": struct.pack("<I", 1) + b"a",
    "read_unicodestring8": struct.pack("<Q", 1) + b"a", "read_unicodestringnl": b"a\n",
}


class GuardTests(unittest.TestCase):
    def test_reviewed_runtime(self):
        verify_runtime()
        with patch("opcode_inspector.guard.REVIEWED_SOURCE", "different"):
            with self.assertRaises(UnsupportedRuntime):
                verify_runtime()
        with patch("opcode_inspector.guard.REVIEWED_LONG_HELPER", "different"):
            with self.assertRaises(UnsupportedRuntime):
                verify_runtime()

    def test_every_selected_reader_benign_and_truncated(self):
        self.assertEqual(set(CASES), READERS)
        for name, data in CASES.items():
            reader = getattr(pickletools, name)
            with self.subTest(reader=name):
                stream = GuardedStream(data, Limits())
                reader(stream)
                self.assertEqual(stream.tell(), len(data))
                with self.assertRaises((ValueError, UnicodeError)):
                    reader(GuardedStream(data[:-1], Limits()))

    def test_every_sized_reader_rejects_before_body_copy(self):
        widths = {
            "read_bytearray8": 8, "read_bytes1": 1, "read_bytes4": 4,
            "read_bytes8": 8, "read_long1": 1, "read_long4": 4,
            "read_string1": 1, "read_string4": 4, "read_unicodestring1": 1,
            "read_unicodestring4": 4, "read_unicodestring8": 8,
        }
        for name, width in widths.items():
            with self.subTest(reader=name):
                stream = GuardedStream((9).to_bytes(width, "little") + b"x" * 9,
                                       Limits(max_operand=8))
                with self.assertRaises(BudgetError):
                    getattr(pickletools, name)(stream)
                self.assertEqual(stream.tell(), width)

    def test_line_readers_reject_before_decode(self):
        names = [name for name in CASES if "nl" in name]
        for name in names:
            with self.subTest(reader=name):
                stream = GuardedStream(b"1" * 9 + b"\n", Limits(max_operand=8))
                with self.assertRaises(BudgetError):
                    getattr(pickletools, name)(stream)
                self.assertEqual(stream.tell(), 0)

    def test_numeric_line_cap_before_conversion(self):
        for name, opcode in (("read_decimalnl_short", "INT"),
                             ("read_decimalnl_long", "LONG"), ("read_floatnl", "FLOAT")):
            stream = GuardedStream(b"1" * 1024 + b"\n", Limits())
            stream.opcode = opcode
            with self.assertRaises(BudgetError):
                getattr(pickletools, name)(stream)
            self.assertEqual(stream.tell(), 0)

    def test_limits_reject_unlimited_and_boolean(self):
        for name in Limits.__dataclass_fields__:
            for value in (True, 0, -1, float("inf"), 10**9):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    Limits(**{name: value})

    def test_read_and_line_boundaries(self):
        stream = GuardedStream(b"1234567\n", Limits(max_operand=8))
        self.assertEqual(stream.readline(), b"1234567\n")
        self.assertEqual(stream.read(0), b"")
        with self.assertRaises(BudgetError):
            stream.read(-1)
        with self.assertRaises(BudgetError):
            GuardedStream(b"xx", Limits(max_bytes=1))

    def test_limits_subclasses_cannot_bypass_contract(self):
        class UnreviewedLimits(Limits):
            pass
        with self.assertRaises(ValueError):
            GuardedStream(b"N.", UnreviewedLimits())


if __name__ == "__main__":
    unittest.main()
