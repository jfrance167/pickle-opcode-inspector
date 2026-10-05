# Security model

This educational lab reads synthetic raw pickle bytes as instructions. Never
deserialize its input or treat exit 0 as permission to do so. The decoder returns
inert primitive dictionaries; global names and mechanism opcodes are observations.

Threats addressed: declared-length allocation before admission; excessive
opcode/report growth; control characters; hidden trailing streams; accidental
restoration or global resolution. Guard all input before decoding; only reviewed
CPython 3.13.7/source/helper are admitted. Decoder APIs are documented in README.

Residual limits: no stack/memo VM validation, FRAME-layout validation, external
buffer validation, semantic safety proof, hard RSS/CPU deadline or OS isolation.
Regular-file stat/fstat and bounded reads detect common type/size changes but
cannot prevent a race before opening, hostile mounts, symlink/device swaps or
blocking I/O. Choose a stable synthetic file on a local filesystem. Fixture
generator shares that assumption and never overwrites different evidence.
Argument decoding and Python object overhead have bounded encoded inputs, not
a process-wide memory cap. Two-line globals may expand to two capped strings.

No networking, privilege changes, external target testing, arbitrary sample
downloads or hostile-sample execution is part of this lab. Use suitable isolated
authorized analysis infrastructure and manual review for hostile evidence.

The runtime source fingerprint is an admission policy, not a cryptographic
attestation against a compromised interpreter or malicious in-process caller.
The standard library and local source files are trusted. Unknown runtimes fail
closed, rather than adapting automatically to new operand-reader behavior.

Report issues privately to the repository owner once a hosted reporting channel
exists. Do not attach executable hostile samples to portfolio records. This local
repository has no configured hosted reporting endpoint or published release.
