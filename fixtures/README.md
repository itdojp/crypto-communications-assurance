# Synthetic fixtures

Every artifact under this directory is synthetic and test-only. It is not derived from a customer, production system, staging system, live scan, upstream repository probe, or private audit.

- `valid/bootstrap-pack.json` remains the frozen bootstrap example.
- `valid/pack-manifest-v1.json` declares a synthetic source tree and path-keyed artifact.
- `valid/pack-lock-v1.json` binds the exact committed synthetic manifest bytes and two exact compatibility-record byte sequences.
- `valid/compatibility-unknown-v1.json` makes no compatibility claim.
- `valid/compatibility-compatible-v1.json` assesses only a fictional target and references synthetic test evidence.
- `invalid/` contains deliberately nonconforming or semantically mismatched candidates used to prove rejection behavior.
- `artifacts/` contains non-sensitive synthetic bytes referenced by fixtures.

New CCA-110 contract fixtures carry `fixtureClassification: synthetic-test-only`; referenced evidence carries `classification: synthetic-test-only`. Legacy bootstrap fixtures remain classified by this directory-level declaration because the frozen bootstrap contract has no fixture metadata field.

A fixture that passes validation remains synthetic. It cannot support a real-world compatibility, security, vulnerability, approval, certification, production-readiness, or release claim.

SHA-256 values cover exact committed bytes. Editing a referenced fixture requires updating external bindings; no fixture contains its own digest.
