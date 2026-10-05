"""Escaped ASCII reports with a bounded final byte count."""

import json

from .guard import BudgetError, Limits


def render(report: dict, format: str = "text", max_output: int = Limits.max_output) -> str:
    """Render trusted inspector records; fail before emitting a partial report."""
    Limits(max_output=max_output)
    if format not in {"text", "json"}:
        raise ValueError("format must be text or json")
    encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    chunks = encoder.iterencode(report)
    prefix = "PICKLE OPCODE INSPECTOR\n" if format == "text" else ""
    parts = [prefix]
    size = len(prefix) + 1
    for chunk in chunks:
        size += len(chunk)
        if size > max_output:
            raise BudgetError("Report output budget exceeded")
        parts.append(chunk)
    return "".join(parts) + "\n"
