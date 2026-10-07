# Pickle Opcode Inspector

Read a raw Python pickle as instructions without restoring its objects. This
learning CLI reports byte offsets, bounded argument previews and explanations
of object-loading mechanisms. A decoded stream **does not prove valid or safe
deserialization**. A report without findings never authorizes loading the file.

## Run the synthetic demo

Requires **CPython 3.13.7** with the reviewed standard-library source. No runtime
third-party dependencies. Other versions or altered pickletools/helper source
produce an explicit unsupported result; adding support requires reader review.

From this project directory on Windows:

```powershell
py -3.13 scripts/make_demo.py examples
py -3.13 -m opcode_inspector examples/hello.pkl --format json
py -3.13 -m opcode_inspector examples/global-review.pkl
py -3.13 -m opcode_inspector examples/trailing.pkl
py -3.13 -m unittest discover -v
```

`py -3.13` must select version 3.13.7; it does not pin that patch version itself.
On an admitted Linux interpreter, use `python` instead. Linux was not tested here.

| Fixture | Expected result | Exit |
|---|---|---:|
| hello.pkl | PROTO, SHORT_BINUNICODE hello, STOP; decoded | 0 |
| global-review.pkl | GLOBAL names collections.Counter; mechanism explained | 1 |
| trailing.pkl | Bytes remain after STOP; malformed | 2 |

The GLOBAL example is hand-authored lookup evidence, not an executable exploit.
All examples are small inert synthetic bytes. [Saved demo results](docs/demo.json)
show the actual reports and CLI outcomes from local verification.

## What it does

Bounded regular-file read → guarded stream → pickletools.genops → inert records
→ ASCII text/JSON. It supports operand decoding for protocols 0–5, including
all 24 reader paths in the admitted implementation. STOP must consume the entire
input. Concatenated pickles and trailing bytes are explicit errors.

States are decoded, malformed, unsupported and limit_exceeded. Exit 0 means
decoded without mechanism findings; 1 decoded with findings; 2 incomplete or
I/O/report error. Neither 0 nor 1 establishes VM stack/memo validity, consistent
frames, loadability, exploitability or safety. STACK_GLOBAL remains unresolved.
Findings explain GLOBAL/REDUCE/BUILD/construction, registry, persistent-ID and
external-buffer mechanisms without invoking them.

| Budget | Default | Hard ceiling |
|---|---:|---:|
| Input bytes | 1 MiB | 4 MiB |
| Opcodes, including STOP | 10,000 | 50,000 |
| Each operand read or line | 16 KiB | 64 KiB |
| Final ASCII output | 1 MiB | 4 MiB |

Use --max-bytes, --max-opcodes, --max-operand or --max-output to lower or raise
within these ceilings. Minimum operand limit is 8 bytes; minimum output 1024.
Only actual integers are accepted by the API; booleans and unlimited settings
are rejected. Numeric text has an additional 1024-byte ceiling including newline.
GLOBAL/INST comprise two individually bounded lines. Previews show at most 64
characters/bytes; large integers show bit length and sign. Output limits fail
before any partial report is emitted.

## Security and limits

No pickle.load, loads or Unpickler calls, content-selected imports, eval/exec,
symbolic execution, rewriting, payload generation, network, member extraction or
external-buffer reads. pickletools imports pickle internally for constants and a
reviewed linear integer helper; importing it is not object restoration.
The two narrowly explained Bandit B403 import exclusions are documented in
[REVIEW.md](REVIEW.md); the original scanner findings are retained.

This host lab accepts synthetic evidence. It is not a malware sandbox or a
process memory/time limiter. Stable local regular files are assumed; filesystem
races and blocking I/O remain. Python object overhead and decoding can expand
memory beyond encoded bytes. Use an isolated authorized lab plus manual parser
review before handling real hostile evidence. See [SECURITY.md](SECURITY.md) and
the source-grounded [reader contract](docs/READER-CONTRACT.md).

ZIP/model containers, URLs, directories, automatic remediation, allowlists,
semantic stack simulation and proving safe deserialization are excluded.

## Verification and development

28 local tests pass on Windows CPython 3.13.7, covering every opcode/reader,
1,000 malformed small inputs, budgets, nonfinite/large scalar previews, offsets,
complete consumption, API non-restoration witnesses, CLI and broken pipes.
These checks supplement source review; monkeypatch tests alone are not a proof.
See [VERIFICATION.md](VERIFICATION.md) for exact checks and unavailable checks.

Bandit 1.9.4 has zero remaining findings after five narrow exclusions: two
pickletools imports and three fixed-command verification-helper sites.
Optional development setup: install requirements-dev.txt in your own environment,
then run `python -m bandit -r opcode_inspector scripts`. No new environment or
dependency installation was needed for local verification. The dev dependency
is directly version-pinned; transitive artifact hashes are not locked.
Prepared tests/Bandit, CodeQL and Dependabot workflows have immutable Action
pins. Hosted checks, repository protections and security eligibility have not
been verified because this repository is local and unpublished.

## Sources, license and learning

Original wrapper and fixtures: MIT, Copyright 2026 Jake Franciosa. No third-party
scanner implementation was copied or run. Python standard library is maintained
under the [PSF license](https://docs.python.org/3/license.html).
Research compared [Picklescan](https://github.com/mmaitre314/picklescan) (MIT) and
[Fickling](https://github.com/trailofbits/fickling) (LGPL-3.0); these broader tools
offer different features and are not dependencies. Primary behavior reference:
[pickletools documentation](https://docs.python.org/3/library/pickletools.html).

Codex implemented and self-reviewed this lab with a small reviewed local Ollama
documentation draft. AI assistance is not an independent security audit.
[LEARNING.md](LEARNING.md) explains the main concepts; [DECISIONS.md](DECISIONS.md)
records tradeoffs. Optional exercise: explain why decoding an isolated REDUCE
opcode can succeed while the bytes need not form a valid restorable object.

## Publication status

See [publication review](PUBLICATION.md) for the October 5 source snapshot, fresh local checks, evidence boundaries and current hosted-check distinction.
