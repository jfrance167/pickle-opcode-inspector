# Learning

Pickle is an instruction stream whose restoration can call Python behavior.
Reading opcode descriptions differs from executing those instructions. A GLOBAL
record can be described without importing its module; a STACK_GLOBAL depends on
runtime stack values and remains unresolved in this lab.

A decoder is not a virtual machine verifier. Isolated opcodes, broken stack
effects or inconsistent frames can decode. This lab deliberately says decoded,
not valid or safe. STOP followed by another stream is rejected to avoid reporting
only an innocent prefix.

Bound lengths before invoking operand conversions. Post-decoding length checks
cannot prevent allocation already done. Sized reads and bounded newline search
gate the reviewed readers; decimal text and binary integers need different
conversion/display policies. Binary integers are displayed by bit length when
large; Unicode and Python-object memory can still expand beyond input bytes.

Source verification must include imported helpers: pickletools imports
pickle.decode_long, so hashing only pickletools would miss that helper's change.
This is a reviewed-runtime boundary, not protection from a compromised host.

Scanner output is evidence, not automatic truth: Bandit flags importing
pickletools because of its general association with pickle. Source/call-path
review justified two narrow import exclusions; no deserialization rule was
globally disabled. Preserve the initial result and explain the decision.

Reusable fixture creator: scripts/make_demo.py accepts a destination directory,
writes three small hand-authored files, repeats safely for identical bytes and
refuses existing different evidence. It neither generates nor loads objects.
