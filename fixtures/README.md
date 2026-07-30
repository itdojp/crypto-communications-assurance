# Synthetic fixtures

Every artifact under this directory is synthetic and test-only. It is not derived from a customer, production system, staging system, live scan, upstream repository probe, or private audit.

- `valid/bootstrap-pack.json` remains the frozen bootstrap example.
- `valid/pack-manifest-v1.json` declares a synthetic source tree and path-keyed artifact.
- `valid/pack-lock-v1.json` binds the exact committed synthetic manifest bytes and two exact compatibility-record byte sequences with distinct subject/target pairs.
- `valid/compatibility-unknown-v1.json` makes no compatibility claim.
- `valid/compatibility-compatible-v1.json` assesses only a fictional target and references synthetic test evidence.
- `invalid/compatibility-invalid-evidence-identifier-v1.json` proves that network-locator-shaped evidence keys are rejected.
- `invalid/compatibility-conflicting-same-pair-v1.json` and `invalid/pack-lock-duplicate-subject-target-v1.json` together prove that a lock cannot bind two assessments of one exact subject/target pair.
- Other files under `invalid/` contain deliberately nonconforming or semantically mismatched candidates used to prove rejection behavior.
- `artifacts/` contains non-sensitive synthetic bytes referenced by fixtures.

New CCA-110 contract fixtures carry `fixtureClassification: synthetic-test-only`; referenced evidence carries `classification: synthetic-test-only`. Legacy bootstrap fixtures remain classified by this directory-level declaration because the frozen bootstrap contract has no fixture metadata field.

A fixture that passes validation remains synthetic. It cannot support a real-world compatibility, security, vulnerability, approval, certification, production-readiness, or release claim.

Compatibility evidence map keys such as `evidence/synthetic-compatibility-result` are bundle-relative identifiers. They are not filesystem paths or network locators; the test harness explicitly maps them to synthetic fixture bytes.

SHA-256 values cover exact committed bytes. Editing a referenced fixture requires updating external bindings; no fixture contains its own digest.

## CCA-120 catalog fixtures

- `valid/property-catalog-v1.json`, `valid/attacker-catalog-v1.json`, and `valid/threat-catalog-v1.json` collectively form the explicitly synthetic positive cross-catalog set; no fourth catalog-set container exists.
- `valid/cca-120-catalog-manifest-v1.json` is a synthetic CCA-110 manifest that binds the three authoritative public catalog byte sequences as `catalog` artifacts under fictional source and producer identities. It is not a live manifest or lock.
- CCA-120 negative fixtures cover malformed and duplicate IDs, key/ID mismatch, dangling references, self-dependency, dependency cycles, empty required relationships, unknown category/relationship, excess map/reference bounds, unsafe safety flags, missing assumptions, and undeclared fields.

Catalog fixture validation does not establish a product claim, vulnerability finding, compatibility, completeness, security proof, certification, or approval.

## CCA-130 module and profile fixtures

CCA-130 adds 11 positive synthetic artifacts: one module catalog, eight profile requests, one golden resolved profile, and one CCA-110 manifest. The requests cover complete multi-module resolution, dependency closure, an unknown module, an unsupported module, conflict propagation, two order permutations of one semantic request, and authoritative property-dependency closure. `valid/resolved-profile-complete-v1.json` is the byte-golden UTF-8/LF result. `valid/cca-130-profile-manifest-v1.json` binds exact synthetic module-catalog, request, and resolved-profile bytes under fictional source/producer identities; it is not a live release manifest or lock.

The 25 new negative artifacts cover malformed module/profile IDs, key/ID mismatch, all four dangling catalog-selection classes, self/dangling/duplicate/cyclic dependencies, duplicate/excessive selections, invalid unsupported form, self/non-canonical/reversed-duplicate/dangling conflicts, intrinsic dependency-closure conflict, catalog and module-catalog digest mismatch, unsafe safety flags, undeclared fields, duplicate requests, and an inconsistent resolved profile.

Unknown, unsupported, and unresolvable results in these fixtures are literal resolution outcomes. They are not execution/evidence statuses. Complete synthetic resolution does not establish product satisfaction, approval, security, certification, production readiness, or release authorization.

## CCA-240 evidence fixtures

`valid/cca-240/` contains 23 explicitly synthetic/test-only public-safe JSON
artifacts: nine result forms covering every status and all three `tool-error`
phases, four provenance records covering public/private forms and all three
allowed origin/use pairs, five freshness records, two records covering opaque-human/no-tool/not-recorded-environment identity, one complete binding set, one
CCA-110 manifest that content-binds representative CCA-240 records, and one
manifest-subject result.

`invalid/cca-240/` contains 48 artifacts covering missing/cross-status fields,
forbidden roles, short/mutable Git identity, every named promotion field,
diagnostic overflow, forbidden synthetic+policy-evaluable classification,
origin/use promotion attempts, every prohibited private opaque metadata field, recorded-environment hostname/credential/customer/path leakage,
subject/input/producer/tool/environment/contract/scope mismatch, dependency mismatch,
freshness decision-order/false-fresh/untrusted-clock errors, missing freshness,
exact digest mismatch, and aggregate-status rejection.

The complete binding fixture binds exact original bytes of one result, provenance,
and freshness record. Every committed private example is an opaque fictional
reference; no private digest, live/customer identity, production/security finding,
or release evidence is present. Fixture acceptance establishes no satisfaction,
approval, certification, product security, compatibility, or release authority.

The `fixtureClassification: synthetic-test-only` marker labels the committed
fixture container and never changes embedded origin/use values. The fictional
records exercising `real` and `policy-evaluable` are lexical/validation examples,
not collected real evidence or an authorization to use evidence in a policy.
