"""Admission and stream bounds for the reviewed CPython operand readers."""

from dataclasses import dataclass
import hashlib
import inspect
# Inspect bounded operand readers; never call a restoration API.
import pickletools  # nosec B403
import sys


REVIEWED_SOURCE = "a4242b8728b0c29d15d9534fac4f7303d9c562a8edb65c87f6bc09f764953412"
REVIEWED_LONG_HELPER = "b94278fc0bda21cb2780e171b4ae34b0f9c12e027b1e1c558066d2d05725692f"
READERS = frozenset("""read_bytearray8 read_bytes1 read_bytes4 read_bytes8
read_decimalnl_long read_decimalnl_short read_float8 read_floatnl read_int4
read_long1 read_long4 read_string1 read_string4 read_stringnl
read_stringnl_noescape read_stringnl_noescape_pair read_uint1 read_uint2
read_uint4 read_uint8 read_unicodestring1 read_unicodestring4
read_unicodestring8 read_unicodestringnl""".split())


class BudgetError(ValueError):
    """A declared operation exceeds the inspection policy."""


class UnsupportedRuntime(ValueError):
    """The operand-reader implementation has not been reviewed."""


@dataclass(frozen=True)
class Limits:
    """Actual integer budgets, with non-overridable hard ceilings."""

    max_bytes: int = 1024 * 1024
    max_opcodes: int = 10000
    max_operand: int = 16384
    max_output: int = 1024 * 1024

    def __post_init__(self):
        for name, ceiling, floor in (
            ("max_bytes", 4 * 1024 * 1024, 1),
            ("max_opcodes", 50000, 1),
            ("max_operand", 65536, 8),
            ("max_output", 4 * 1024 * 1024, 1024),
        ):
            value = getattr(self, name)
            if type(value) is not int or not floor <= value <= ceiling:
                raise ValueError(f"{name} must be an integer from {floor} to {ceiling}")


def verify_runtime():
    """Fail closed on an unreviewed version, source or operand-reader set."""
    if sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 13, 7):
        raise UnsupportedRuntime("Only reviewed CPython 3.13.7 is supported")
    try:
        digest = hashlib.sha256(inspect.getsource(pickletools).encode()).hexdigest()
        long_digest = hashlib.sha256(inspect.getsource(pickletools.decode_long).encode()).hexdigest()
    except (OSError, TypeError) as error:
        raise UnsupportedRuntime("Cannot verify pickletools source") from error
    names = {op.arg.reader.__name__ for op in pickletools.opcodes if op.arg}
    if digest != REVIEWED_SOURCE or long_digest != REVIEWED_LONG_HELPER or names != READERS:
        raise UnsupportedRuntime("Unreviewed pickletools implementation")


class GuardedStream:
    """Only tell/read/readline; no unbounded reads or decoder-selected seek.

    Caller identifies the next opcode before advancing genops. Decimal and
    float text is capped at 1024 encoded bytes before numeric conversion.
    """

    def __init__(self, data: bytes, limits: Limits):
        if type(data) is not bytes or type(limits) is not Limits:
            raise ValueError("Input must be bytes with reviewed Limits")
        if len(data) > limits.max_bytes:
            raise BudgetError("Input byte budget exceeded")
        self.data = data
        self.limits = limits
        self.pos = 0
        self.opcode = ""

    def tell(self):
        return self.pos

    def read(self, size):
        if type(size) is not int or size < 0 or size > self.limits.max_operand:
            raise BudgetError("Operand read budget exceeded")
        end = min(len(self.data), self.pos + size)
        result = self.data[self.pos:end]
        self.pos = end
        return result

    def readline(self):
        cap = self.limits.max_operand
        if self.opcode in {"INT", "LONG", "FLOAT", "PUT", "GET"}:
            cap = min(cap, 1024)
        end = self.data.find(b"\n", self.pos, self.pos + cap)
        if end < 0:
            if len(self.data) - self.pos > cap:
                raise BudgetError("Operand line budget exceeded")
            end = len(self.data)
        else:
            end += 1
        result = self.data[self.pos:end]
        self.pos = end
        return result
