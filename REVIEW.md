# ECC self-review — October 5, 2026

Scope: entire new project, including the initial 84131a3 guard commit and all
remaining task code, tests, fixtures, CLI/report callers, verification helper,
CI and documentation. Reviewed the actual source with ecc-code-review's pinned
checklist and consolidated evidence with ecc-verification-loop. This is Codex
self-review, not independent agent review. The native ECC plugin is not installed.

## Findings corrected during implementation

- guard.py runtime admission: hashing pickletools alone would not cover imported
  pickle.decode_long. Added the separately inspected helper source fingerprint
  and a mismatch regression. Limits subclasses are now rejected at core/stream
  API admission, preserving the reviewed budget type.
- verify_local.py workflow policy: assertions would disappear under Python -O,
  allowing a broken policy to escape detection. Replaced them with explicit
  ValueError checks. Verification also passed under -O at the then-current
  26-test milestone; final 28-test suite passed after the later boundary cases.
- Verification helper now retains malformed/missing demo and syntax/YAML failure
  outcomes instead of silently claiming successful checks. Initial failed
  scanner evidence and subsequent fixes are preserved.
- Demo generator now reads at most expected length + 1 from existing fixtures;
  refuses non-files/symlinks/different content. It retains the stable-filesystem
  assumption and does not claim race isolation.

## Scanner dispositions

Bandit initially flagged two B403 pickletools imports. Official pickletools docs,
all 24 reader paths, genops and imported long helper were inspected. Our callers
decode inert records and never invoke restoration. Two line-level B403 exclusions
have nearby explanations; source-backed reader contract and forbidden-call
witnesses support the decision. No deserialization rule is disabled globally.

The verification helper initially added seven findings. Switched YAML to
safe_load and removed three assertions. Reviewed three B404/B603 sites as narrow
false positives: commands come exclusively from fixed local tables, sys.executable
and fixed synthetic fixture names; no shell, content-selected command or remote
execution exists. Each subprocess has a timeout. Those three sites have local
explanations and exclusions. This is five excluded sites total, not five ignored
vulnerabilities. Other scanner rules remain active. Final Bandit: no findings or
errors. Original findings remain in docs/bandit-before-reviewed-imports.json and
docs/verification-20261005/bandit.json.

## Final assessment

No unresolved actionable defects found in the reviewed scope. The source has no
object restoration, content-selected lookup/import or sample execution path.
Structural reports use ASCII escaping, explicit errors, bounded previews and
STOP/full-consumption checks. Every argument-reader path has direct witnesses;
the full 68-opcode set has inert decoding coverage. A deliberately removed read
guard failed its regression and was restored byte-for-byte.

| Severity | Unresolved count | Status |
|---|---:|---|
| Critical | 0 | pass |
| High | 0 | pass |
| Medium | 0 | pass |
| Low | 0 | pass |

Verdict: APPROVE for the local synthetic lab. This does not authorize publication,
merge, deployment or hostile-evidence use. Manual parser review and suitable
isolation remain before real hostile evidence. No hard RSS/time guarantee, VM
semantics, FRAME validation, hosted CodeQL/CI or Linux validation is claimed.
