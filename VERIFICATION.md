# Verification — October 5, 2026

Latest full record: docs/verification-reviewed-20261005/results.json and logs.
Windows CPython 3.13.7. Stage 1's seven-reader-contract tests passed before
stage 2; final **28 tests pass**, including 68 opcode cases and 1,000 deterministic
small malformed inputs. No object deserialization or hostile sample was run.

| Check | Outcome | Evidence/command |
|---|---|---|
| Tests | PASS, 28 | `python -m unittest discover -v`; reviewed tests.log |
| Bandit 1.9.4 | PASS, zero remaining findings/errors, five reviewed site exclusions | `python -m bandit -r opcode_inspector scripts`; reviewed bandit.json |
| Syntax | PASS, seven app/helper files | AST parsing in verify_local.py |
| Workflow policy | PASS locally | YAML parse, push branches, 40-character Action SHAs, checkout credentials false |
| Demo CLI | PASS, 0/1/2 | hello/global-review/trailing, reviewed demo.json and per-demo logs |
| Read-guard mutation | Detected; original source restored byte-for-byte | docs/mutation-witness.json and log |
| Optimized verification | PASS at 26-test milestone | docs/verification-optimized-20261005; explicit policy failures survive -O |
| Git whitespace/fixture bytes | PASS | Final staged diff and indexed fixture comparison recorded in STATE |
| Narrow credential-pattern scan | See final STATE | Not a comprehensive secret-scanner guarantee |
| Types/lint | NOT RUN | No configured checker established |
| Linux, hosted CI/CodeQL | NOT RUN | No Linux run or hosted repository |
| Alternative runtimes | Unsupported by policy | Version/source mismatch returns unsupported |

The initial two import findings and seven helper findings are retained. Later
records cover their corrections and reviewed exclusions. Final affected reruns
passed; unaffected suites were not repeated after documentation-only edits.
See REVIEW.md for ECC review scope and limitations.

Reusable verification: `python scripts/verify_local.py FRESH_OUTPUT_DIRECTORY`.
It requires already installed Bandit and optional PyYAML, installs nothing, and
records PASS/FAIL/NOT RUN with commands/exit codes. Paths in checked-in records
are normalized for portfolio privacy; original local evidence is retained under
ignored .drafts. Fixture regeneration: `python scripts/make_demo.py DIRECTORY`;
idempotent for identical bytes and refuses different evidence.

CI is prepared with previously verified immutable checkout/setup-python/CodeQL
pins, minimum permissions, manual checks and scheduled CodeQL. No hosted security
eligibility, branch protections, secret scanning, push protection, Actions runs or
alerts were checked. No publication is authorized. Bandit is directly pinned;
development dependencies lack a transitive artifact-hash lock.
