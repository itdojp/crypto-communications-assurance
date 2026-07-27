# Schemas

JSON files in this directory are the authoritative machine contracts. Every schema is closed and uses JSON Schema Draft 2020-12.

| Contract | Role |
| --- | --- |
| `cryptocomm-pack/v1` | Frozen bootstrap envelope. Its existing `planned` compatibility value remains intent only. |
| `cryptocomm-pack-manifest/v1` | Publisher/source declaration for one immutable pack and path-keyed exact-byte artifact bindings. |
| `cryptocomm-pack-lock/v1` | Consumer-side resolution of exact manifest bytes, source identity, resolver identity, and optional compatibility-record references. |
| `cryptocomm-compatibility-record/v1` | Assessment of one exact manifest subject against one exact target identity. |
| `cryptocomm-property-catalog/v1` | ID-keyed protocol-neutral property outcomes, bounded dependencies, and abstract evidence needs. |
| `cryptocomm-attacker-catalog/v1` | Separate ID-keyed attacker capabilities and bounded attacker models. |
| `cryptocomm-threat-catalog/v1` | ID-keyed bounded threats referencing capabilities and affected properties. |

The bootstrap contract is not renamed, replaced, or reinterpreted by the three CCA-110 contracts.

SHA-256 covers exact referenced bytes; version 1 performs no implicit JSON canonicalization. Strict contract decoding is limited to 1,048,576 bytes and 128 nested object/array containers per artifact and rejects invalid UTF-8, duplicate decoded member names at every nesting level, comments, trailing commas, and trailing data before schema or semantic validation. A manifest has no self-digest. The lock stores the SHA-256 of separately supplied manifest bytes.

Compatibility records use `unknown`, `compatible`, `incompatible`, or `unsupported`; only compatible/incompatible require content-addressed evidence, while unsupported requires explicit reason and scope. One lock can bind at most one record for an exact subject/target pair. Evidence map keys are bounded bundle-relative identifiers rather than repository authorities, network locators, private or local paths, or provenance records.

CCA-120 entry identifiers use `property.<domain>.<name>`, `capability.<domain>.<name>`, `attacker.<name>`, and `threat.<domain>.<name>`. The catalog schemas are closed and bounded to 64 properties, 48 capabilities, 16 attacker models, and 64 threats. The initial reviewed artifacts contain 40 properties, 28 capabilities, 8 attacker models, and 36 threats. They contain no source/producer identity, execution status, risk score, control, evidence result, approval, or release field.

Generic JSON Schema validation is separate from cross-artifact semantic validation in `packages/contracts`. Schema conformance alone establishes none of truth, completeness, compatibility, security, certification, human approval, production readiness, or release readiness.

See [Contract versioning and migration](../docs/CONTRACT_VERSIONING.md), [ADR 0002](../docs/decisions/0002-pack-manifest-lock-and-compatibility.md), and [ADR 0003](../docs/decisions/0003-security-catalog-separation-and-relationships.md).
