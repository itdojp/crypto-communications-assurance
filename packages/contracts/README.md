# Contracts package

This private package provides two separate repository-local validation layers:

1. `compileContract` compiles an independently supplied closed Draft 2020-12 JSON Schema with strict AJV behavior.
2. Pure semantic validators parse the exact supplied manifest and compatibility-record bytes, receive the already parsed lock, and check manifest/lock/compatibility bindings without network, filesystem resolution, execution, or mutation. Callers must separately schema-validate the JSON value parsed from those same exact bytes before semantic validation.

The package is not published. Validation conveys no human approval, compatibility guarantee, security proof, certification, production readiness, or release authority.

## Semantic diagnostics

| Code | Meaning |
| --- | --- |
| `MANIFEST_BYTES_INVALID` | Supplied manifest bytes are not a JSON object; separate schema validation is still required. |
| `MANIFEST_DIGEST_MISMATCH` | Lock digest does not bind the exact supplied manifest bytes. |
| `PACK_ID_MISMATCH` | Manifest and lock pack IDs differ. |
| `PACK_VERSION_MISMATCH` | Manifest and lock pack versions differ. |
| `SOURCE_IDENTITY_MISMATCH` | Repository, exact revision, or source tree differs. |
| `IMPLEMENTATION_IDENTITY_INVALID` | Producer, resolver, or target implementation identity is incomplete or non-exact. |
| `COMPATIBILITY_RECORD_BYTES_INVALID` | Supplied compatibility-record bytes are not a JSON object; separate schema validation is still required. |
| `COMPATIBILITY_RECORD_MISSING` | A lock reference has no supplied record. |
| `COMPATIBILITY_RECORD_UNREFERENCED` | A supplied record is not declared by the lock. |
| `COMPATIBILITY_RECORD_ID_MISMATCH` | Lock key and record ID differ. |
| `COMPATIBILITY_RECORD_DIGEST_MISMATCH` | Lock reference does not bind exact record bytes. |
| `COMPATIBILITY_SUBJECT_MISMATCH` | Record subject differs from the exact manifest identity. |
| `COMPATIBILITY_TARGET_MISMATCH` | Lock reference and record target differ. |
| `COMPATIBILITY_EVIDENCE_REQUIRED` | Compatible/incompatible state lacks content-addressed evidence. |
| `LEGACY_STATUS_PROMOTION_FORBIDDEN` | Bootstrap `planned` was mapped to a state other than `unknown`. |

Diagnostics are bounded, deterministic, machine-readable, and returned in stable code/path order. They are evidence only.
