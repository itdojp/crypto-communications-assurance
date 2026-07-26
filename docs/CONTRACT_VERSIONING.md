# Contract versioning and migration

## Contract inventory

| `schemaVersion` | Role | Evolution status |
| --- | --- | --- |
| `cryptocomm-pack/v1` | Frozen bootstrap envelope | Its existing meaning is immutable; `planned` remains intent only. |
| `cryptocomm-pack-manifest/v1` | Publisher/source declaration for one immutable pack | New CCA-110 contract. |
| `cryptocomm-pack-lock/v1` | Consumer resolution of exact manifest bytes and resolver identity | New CCA-110 contract. |
| `cryptocomm-compatibility-record/v1` | Evidence-backed assessment of an exact subject against an exact target | New CCA-110 contract. |

Each value identifies one closed JSON Schema Draft 2020-12 contract. The manifest, lock, and compatibility record have separate identities because their authorities and content bindings differ.

## Immutable meaning

- A `schemaVersion` value has exactly one meaning.
- A breaking semantic or validation change requires a new contract ID/version.
- A contract must not reinterpret an existing field, widen an authority boundary, or silently accept a previously invalid value in place.
- Documentation may clarify an existing meaning but must not become a second machine authority.
- Schema conformance is only schema conformance; it is not truth, completeness, compatibility, security, approval, certification, or release readiness.

Because these contracts are closed, even an apparently optional field can change the accepted document set. Such evolution requires an explicit review and versioning decision rather than an unreviewed in-place edit.

## Explicit migration

A migration is a separately reviewed deterministic transformation. Its specification must identify:

- exact source and destination contract IDs;
- exact input bytes or their content digest;
- deterministic output rules;
- bounded machine-readable failure diagnostics;
- information that cannot be represented without loss;
- validation for positive, negative, and ambiguous inputs;
- the human decision boundary retained after migration.

Ambiguous, lossy, unrecognized, or under-specified migrations fail closed. No validator in CCA-110 performs an implicit migration.

Legacy bootstrap `planned` has no compatibility meaning. An explicit migration may map `planned` only to `unknown`, or reject the input pending assessment. Mapping `planned` to `compatible`, `incompatible`, or `unsupported` is rejected as `LEGACY_STATUS_PROMOTION_FORBIDDEN`.

## Content binding across versions

SHA-256 values cover exact referenced bytes. JSON member order, whitespace, encoding, and line endings therefore affect a digest. Version 1 defines no implicit JSON canonicalization. A manifest never contains its own digest; a lock binds the separately supplied manifest bytes.

## Human authority

Version selection, compatibility commitments, migration acceptance, risk acceptance, merge, release, and publication remain human decisions. Automation can validate declared contracts and content bindings but cannot approve them.
