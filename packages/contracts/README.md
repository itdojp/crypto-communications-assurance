# Contracts package

This private package provides three separate repository-local validation layers:

1. `decodeStrictJsonObject` decodes at most 1,048,576 exact input bytes as fatal UTF-8 and strict JSON with at most 128 nested object/array containers. It rejects comments, trailing commas, trailing data, a non-object root, and duplicate decoded member names at every nesting level (including duplicates expressed with JSON escapes).
2. `compileContractBytes` passes only that strict-decoded object to a caller-supplied closed Draft 2020-12 schema compiled with strict AJV behavior. `compileContract` remains the generic schema-compilation primitive for already decoded trusted values.
3. Pure semantic validators strict-decode the exact supplied manifest, lock, and compatibility-record bytes and check cross-artifact bindings without network, filesystem resolution, execution, or mutation. Callers must separately schema-validate each object decoded from those same exact bytes before treating semantic results as contract validation.

The decoder does not canonicalize or rewrite JSON. SHA-256 binding continues to cover the original byte sequence supplied by the caller, not a re-serialized object. The 1,048,576-byte limit applies independently to each manifest, lock, and compatibility record and is checked before UTF-8 decoding. The 128-container limit is checked with a non-recursive structural preflight before parsing, and duplicate traversal is also non-recursive.

A v1 lock may reference at most one compatibility record for each exact subject/target pair. Multiple supporting results belong in that single record's evidence map. Evidence map keys are bounded bundle-relative identifiers, not repository authorities, URLs, private or absolute paths, or provenance records.

The package is not published. Validation conveys no human approval, compatibility guarantee, security proof, certification, production readiness, or release authority.

## Strict-decoding diagnostics

| Code | Meaning |
| --- | --- |
| `JSON_INPUT_TOO_LARGE` | One exact JSON input exceeds 1,048,576 bytes. |
| `JSON_INVALID_UTF8` | Exact bytes are not valid UTF-8. |
| `JSON_NESTING_TOO_DEEP` | Input exceeds 128 nested object/array containers. |
| `JSON_SYNTAX_INVALID` | Input is not strict JSON; comments, trailing commas, and trailing data are rejected. |
| `JSON_DUPLICATE_MEMBER` | An object repeats a decoded member name at any nesting level. |
| `JSON_ROOT_NOT_OBJECT` | The strict JSON root is not an object. |

## Semantic diagnostics

| Code | Meaning |
| --- | --- |
| `MANIFEST_DIGEST_MISMATCH` | Lock digest does not bind the exact supplied manifest bytes. |
| `PACK_ID_MISMATCH` | Manifest and lock pack IDs differ. |
| `PACK_VERSION_MISMATCH` | Manifest and lock pack versions differ. |
| `SOURCE_IDENTITY_MISMATCH` | Repository, exact revision, or source tree differs. |
| `IMPLEMENTATION_IDENTITY_INVALID` | Producer, resolver, or target implementation identity is incomplete or non-exact. |
| `COMPATIBILITY_RECORD_LIMIT_EXCEEDED` | More than 256 record references or record-byte entries were supplied; validation fails with one bounded aggregate diagnostic. |
| `COMPATIBILITY_RECORD_MISSING` | A lock reference has no supplied record. |
| `COMPATIBILITY_RECORD_UNREFERENCED` | A supplied record is not declared by the lock. |
| `COMPATIBILITY_RECORD_ID_MISMATCH` | Lock key and record ID differ. |
| `COMPATIBILITY_RECORD_DIGEST_MISMATCH` | Lock reference does not bind exact record bytes. |
| `COMPATIBILITY_SUBJECT_MISMATCH` | Record subject differs from the exact manifest identity. |
| `COMPATIBILITY_TARGET_MISMATCH` | Lock reference and record target differ. |
| `COMPATIBILITY_PAIR_DUPLICATE` | A lock references multiple records for the same exact subject/target pair. |
| `COMPATIBILITY_EVIDENCE_REQUIRED` | Compatible/incompatible state lacks content-addressed evidence. |
| `LEGACY_STATUS_MIGRATION_FORBIDDEN` | A legacy/new-state pair is not the sole accepted `planned` to `unknown` mapping. |

Diagnostics are bounded, deterministic, machine-readable, and returned in stable code/path order. They are evidence only.
