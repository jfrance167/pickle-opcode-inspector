"""Inert opcode records and conservative mechanism explanations."""

import hashlib
import math
# Reviewed genops only; no object restoration. See docs/READER-CONTRACT.md.
import pickletools  # nosec B403
import warnings

from .guard import BudgetError, GuardedStream, Limits, UnsupportedRuntime, verify_runtime


NOTICE = "Decoded opcodes do not prove valid or safe deserialization. Never load unknown pickle files."
MECHANISMS = {
    "GLOBAL": "Names a global; restoring objects may import or resolve it.",
    "STACK_GLOBAL": "Resolves names from the runtime stack; names are not resolved here.",
    "REDUCE": "Object restoration may call a stack-selected callable.",
    "BUILD": "Restoration may apply state or invoke an object's state hook.",
    "INST": "Legacy class lookup and instance restoration mechanism.",
    "OBJ": "Legacy stack-selected instance restoration mechanism.",
    "NEWOBJ": "Restoration may invoke a type's object construction method.",
    "NEWOBJ_EX": "Object construction can include keyword arguments.",
    "EXT1": "Restoration uses an external extension registry.",
    "EXT2": "Restoration uses an external extension registry.",
    "EXT4": "Restoration uses an external extension registry.",
    "PERSID": "Restoration may invoke a persistent-ID handler.",
    "BINPERSID": "Restoration may invoke a persistent-ID handler.",
    "NEXT_BUFFER": "Restoration requires an external buffer; none is accessed here.",
    "READONLY_BUFFER": "Restoration changes an external buffer's view semantics.",
}


def preview(arg):
    """Bounded scalar descriptions, including nonfinite floats and large ints."""
    if arg is None or type(arg) is bool:
        return arg
    if type(arg) is int:
        if arg.bit_length() <= 256:
            return arg
        return {"type": "integer", "bits": arg.bit_length(), "negative": arg < 0}
    if type(arg) is float:
        return arg if math.isfinite(arg) else {"type": "float", "value": repr(arg)}
    if isinstance(arg, (bytes, bytearray)):
        return {"type": type(arg).__name__, "length": len(arg),
                "hex_prefix": arg[:64].hex(), "truncated": len(arg) > 64}
    if type(arg) is str:
        return {"type": "string", "length": len(arg), "prefix": arg[:64],
                "truncated": len(arg) > 64}
    raise UnsupportedRuntime("Unreviewed decoded argument type")


def inspect_bytes(data: bytes, limits: Limits | None = None) -> dict:
    """Decode one bounded stream; never instantiate or resolve serialized objects.

    decoded means STOP plus complete byte consumption, not VM validity.
    API misuse (non-bytes/invalid Limits) raises ValueError. Format/policy/runtime
    outcomes return explicit states with any already decoded inert records.
    """
    limits = limits if limits is not None else Limits()
    if type(limits) is not Limits or type(data) is not bytes:
        raise ValueError("Expected bytes and Limits")
    report = {"state": "malformed", "size_bytes": len(data), "notice": NOTICE,
              "opcodes": [], "findings": []}
    if len(data) > limits.max_bytes:
        report.update(state="limit_exceeded", error={"offset": 0, "message": "Input byte budget exceeded"})
        return report
    report["sha256"] = hashlib.sha256(data).hexdigest()
    stream = GuardedStream(data, limits)
    offset = 0
    try:
        verify_runtime()
        ops = pickletools.genops(stream)
        while True:
            offset = stream.tell()
            if len(report["opcodes"]) >= limits.max_opcodes:
                raise BudgetError("Opcode budget exceeded")
            code = data[offset:offset + 1].decode("latin-1")
            info = pickletools.code2op.get(code)
            stream.opcode = info.name if info is not None else ""
            if info is not None and info.proto > 5:
                raise UnsupportedRuntime("Unsupported opcode protocol")
            # Invalid escape warnings would bypass the escaped report channel.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                op, arg, pos = next(ops)
            if op.name == "PROTO" and arg > 5:
                raise UnsupportedRuntime("Only pickle protocols 0 through 5 are supported")
            record = {"offset": pos, "end": stream.tell(), "name": op.name,
                      "minimum_protocol": op.proto, "argument": preview(arg)}
            report["opcodes"].append(record)
            if op.name in MECHANISMS:
                report["findings"].append({"offset": pos, "opcode": op.name,
                                           "explanation": MECHANISMS[op.name]})
            if op.name == "STOP":
                if stream.tell() != len(data):
                    raise ValueError("Trailing bytes or concatenated streams after STOP")
                report["state"] = "decoded"
                break
    except (BudgetError, UnsupportedRuntime, ValueError, OverflowError) as error:
        report["state"] = ("limit_exceeded" if isinstance(error, BudgetError) else
                           "unsupported" if isinstance(error, UnsupportedRuntime) else "malformed")
        report["error"] = {"offset": offset, "message": str(error)[:512]}
    return report
