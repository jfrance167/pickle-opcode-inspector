# Stage 1 acceptance — October 5, 2026

Stage 1 completed before stage 2. Seven tests passed on CPython 3.13.7.
Reviewed all 24 selected pickletools argument-reader functions and _genops.
Normalized full-module source SHA-256:
`a4242b8728b0c29d15d9534fac4f7303d9c562a8edb65c87f6bc09f764953412`.
Runtime admission checks version, source hash and reader-name set. No automatic
support for newer Python, alternate interpreters or altered source.
The imported pickle.decode_long helper was also inspected: linear signed
int.from_bytes, source SHA-256
`b94278fc0bda21cb2780e171b4ae34b0f9c12e027b1e1c558066d2d05725692f`.
Its source fingerprint is included because pickletools imports that helper.

The bundled 3.12.14 source was also inspected and had the same module hash, but
is deliberately not admitted: only the selected 3.13.7 runtime was accepted.

| Reader family | Before-conversion bound | Witness |
|---|---|---|
| uint1/2/4/8, int4, float8 | read exactly 1–8 bytes; minimum operand cap is 8 | Benign and truncated inputs for each |
| bytes1/4/8, bytearray8, string1/4, unicode1/4/8 | Header is at most 8 bytes. Guard rejects body read larger than cap before slicing, decoding or bytearray creation | Oversize case for all nine types |
| long1/4 | Length header <=4 bytes, body read capped before linear int.from_bytes | Oversize body rejected before cursor advances |
| stringnl/noescape/pair, unicodestringnl | find newline within cap without copying; reject overlong before escape/Unicode decoding | Every line-reader path, including first line of pair |
| decimal short/long and floatnl | Same line gate; stricter 1024-byte numeric-line ceiling including newline | Conversion never receives over-ceiling line |

GLOBAL/INST pair readers can return two bounded strings joined with one space;
their decoded argument is at most twice the per-read cap plus one character.
UTF-8/raw-unicode/escape decoding is bounded by admitted encoded input but Python
object overhead and string representation may expand memory; this is not an RSS
guarantee. Numeric strings are <=1024 bytes; binary integers <=64 KiB and are
reported by bit length above a small display threshold, avoiding huge decimal
conversions. Underlying readers use only tell/read/readline on this stream; no
seek, readinto, unbounded read or external buffer access occurs in this source.

Tests enumerate the exact reader set so omission fails acceptance. Input is
already bounded before a guarded stream exists. genops is advanced only after
the caller identifies the opcode for numeric-line policy. Source changes require
new inspection/tests and an explicit runtime-contract update, not a hash bypass.

This proves the documented per-read allocation gates for the reviewed operand
paths, not pickle VM semantics, exact total memory, process CPU deadlines,
FRAME layout, memo/stack consistency, safe deserialization or hostile-host
isolation. No unpickling was performed.
