"""CLI for stable local raw pickle evidence; no object restoration."""

import argparse
import os
from pathlib import Path
import stat
import sys

from .core import inspect_bytes
from .guard import BudgetError, Limits
from .report import render


def read_input(path: Path, limits: Limits) -> bytes:
    """Bound regular-file bytes; this does not isolate filesystem races."""
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Input must be a regular file")
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Input must be a regular file")
        if info.st_size > limits.max_bytes:
            raise BudgetError("Input byte budget exceeded")
        data = stream.read(limits.max_bytes + 1)
    if len(data) > limits.max_bytes:
        raise BudgetError("Input byte budget exceeded")
    return data


def main(argv=None) -> int:
    """Exit 0 decoded/no findings, 1 decoded/findings, 2 incomplete or I/O error."""
    cli = argparse.ArgumentParser(description="Inspect pickle opcodes without restoring objects")
    cli.add_argument("file", type=Path)
    cli.add_argument("--format", choices=("text", "json"), default="text")
    for name in Limits.__dataclass_fields__:
        cli.add_argument("--" + name.replace("_", "-"), type=int, default=getattr(Limits, name))
    args = cli.parse_args(argv)
    try:
        limits = Limits(**{name: getattr(args, name) for name in Limits.__dataclass_fields__})
        report = inspect_bytes(read_input(args.file, limits), limits)
        output = render(report, args.format, limits.max_output)
        sys.stdout.write(output)
        sys.stdout.flush()
    except (OSError, ValueError) as error:
        sys.stderr.write("Inspection/output error: " + ascii(str(error)) + "\n")
        return 2
    if report["state"] != "decoded":
        return 2
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    status = main()
    if status == 2:
        try:
            sys.stdout.flush()
        except OSError:
            sys.stdout = None
    raise SystemExit(status)
