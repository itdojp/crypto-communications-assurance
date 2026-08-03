# Contracts package

This private package provides separate repository-local validation authorities:

1. `decodeStrictJsonObject` decodes at most 1,048,576 exact input bytes as fatal UTF-8 and strict JSON with at most 128 nested object/array containers. It rejects comments, trailing commas, trailing data, a non-object root, and duplicate decoded member names at every nesting level (including duplicates expressed with JSON escapes).
2. `compileContractBytes` passes only that strict-decoded object to a caller-supplied closed Draft 2020-12 schema compiled with strict AJV behavior. `compileContract` remains the generic schema-compilation primitive for already decoded trusted values.
3. Pure semantic validators strict-decode the exact supplied manifest, lock, and compatibility-record bytes and check cross-artifact bindings without network, filesystem resolution, execution, or mutation. Callers must separately schema-validate each object decoded from those same exact bytes before treating semantic results as contract validation.
4. CCA-240 validators preserve strict decode, schema conformance, cross-contract semantics, pure freshness assessment, and deterministic serialization as separate operations. The binding-set validator verifies exact original bytes and repeated identities without canonicalizing external input.
5. CCA-210 `validateAeRenderPlan` exact-byte/schema/semantically validates the operator plan, all five CCA inputs, existing Context Pack bytes, the exact five-schema upstream pin, and renderer source. `renderAeNativeArtifacts` is separate and accepts only the successful validation token.

The decoder does not canonicalize or rewrite JSON. SHA-256 binding continues to cover the original byte sequence supplied by the caller, not a re-serialized object. The 1,048,576-byte limit applies independently to each manifest, lock, and compatibility record and is checked before UTF-8 decoding. The 128-container limit is checked with a non-recursive structural preflight before parsing, and duplicate traversal is also non-recursive.

A v1 lock may reference at most one compatibility record for each exact subject/target pair. Multiple supporting results belong in that single record's evidence map. Evidence map keys are bounded bundle-relative identifiers, not repository authorities, URLs, private or absolute paths, or provenance records.

The package is not published. Validation conveys no human approval, compatibility guarantee, security proof, certification, production readiness, or release authority.

## CCA-210 exact-pin renderer

`ae-renderer.ts` is data-only and pure: it performs no file lookup, symlink
resolution, network access, mutable-ref discovery, current-time read, upstream
execution, policy evaluation, or write. Callers supply all exact bytes. The plan
asserts repository-relative paths and `rejectSymlinks: true`; the embedding
caller remains responsible for opening files without following a symlink before
supplying their bytes.

Every supplied Context Pack is unconditionally validated against the exact
pinned Context Pack schema; v1 does not permit a plan to opt out.

Semantic checks cover exact digests and lengths; CCA/upstream contract and pin
identity; resolved-profile/catalog closure; mapping/output completeness;
duplicate and dangling IDs; exact property/claim and threat identity; explicit
native enum membership; evidence-mapping unions; literal unsupported/lossy
decisions; Context Pack element references restricted to scope-selected packs;
full target commit/tree; scope and
trust-boundary consistency; renderer-source identity; and exact re-resolution
of the resolved profile from its embedded request facts. Diagnostics are
deduplicated, bounded to 256, and sorted by code, path, and message. Validation
and native-schema failures have `error` severity; a successful render can also
return `information` diagnostics that keep unsupported/excluded mapping and
known projection loss literal for CCA-240 recording. Informational overflow is
represented by one informational summary rather than an error-severity record.

Output uses UTF-8, two spaces, LF, one final newline, fixed field order, and
code-point sorting, including optional source-reference descriptions as the
final source-reference tie-breaker. It omits native `generatedAt`, summaries, deployment, gate
policy, and every prohibited artifact kind. It generates no Context Pack or
claim-evidence/result/policy/review/release surface. Exact output bytes are
recorded by the existing CCA-240 contracts rather than a new render-result
contract.

Explicit native lane/kind and STRIDE/CWE selections are not automatic
crosswalks. `operational-procedure` and `human-review` stay unsupported unless a
plan records a narrower lossy projection, and `waiver` is never human review.
Schema-valid output is bounded exact-pin shape evidence only.

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

## CCA-120 catalog validation

CCA-120 reuses `decodeStrictJsonObject` for each property, attacker, and threat catalog. Callers separately apply the three closed schemas and then use `validatePropertyCatalog`, `validateAttackerCatalog`, `validateThreatCatalog`, or `validateCatalogSet` for deterministic semantic checks. The complete set validator derives all objects from the supplied exact bytes and performs no network, filesystem resolution, execution, cryptographic protocol, or external-tool operation.

Semantic validation covers stable namespace syntax, map-key/ID consistency, duplicate semantic IDs, category/domain agreement, bounded maps and references, dangling property/capability references, self-dependency, property cycles, explicit assumptions/exclusions/preconditions/impact, required category coverage, and the data-only safety boundary.

### Catalog diagnostic codes

| Code | Meaning |
| --- | --- |
| `CATALOG_STRUCTURE_INVALID` | Strict-decoded data lacks a structure needed for semantic inspection. |
| `CATALOG_ID_INVALID` | Catalog identity syntax is invalid or unbounded. |
| `ENTRY_ID_INVALID` | Entry identity does not use its required namespace. |
| `ENTRY_KEY_ID_MISMATCH` | Map key and contained entry ID differ. |
| `DUPLICATE_ENTRY_ID` | Multiple entries declare one semantic ID. |
| `ENTRY_DOMAIN_MISMATCH` | ID domain and category/domain field differ. |
| `PROPERTY_REFERENCE_DANGLING` | No declared property satisfies a reference. |
| `CAPABILITY_REFERENCE_DANGLING` | No declared capability satisfies a reference. |
| `PROPERTY_SELF_DEPENDENCY` | A property directly depends on itself. |
| `PROPERTY_DEPENDENCY_CYCLE` | The bounded property graph contains a cycle. |
| `ATTACKER_CAPABILITIES_REQUIRED` | An attacker model has no capability reference. |
| `THREAT_CAPABILITIES_REQUIRED` | A threat has no capability reference. |
| `THREAT_PROPERTIES_REQUIRED` | A threat has no affected-property reference. |
| `CATEGORY_UNKNOWN` | Category/domain is outside the closed vocabulary. |
| `RELATIONSHIP_UNKNOWN` | Relationship field or reference namespace is not defined by v1. |
| `EVIDENCE_KIND_UNKNOWN` | Abstract evidence lane is outside the closed vocabulary. |
| `CATALOG_SIZE_LIMIT_EXCEEDED` | An entry map exceeds its bounded contract maximum. |
| `REFERENCE_LIMIT_EXCEEDED` | A relationship exceeds its bounded reference maximum. |
| `REQUIRED_CATEGORY_MISSING` | Complete catalog coverage omits a required scope category/domain. |
| `SAFETY_BOUNDARY_VIOLATION` | Data-only/no-network/no-secret flags are not all false. |
| `ASSUMPTIONS_REQUIRED` / `EXCLUSIONS_REQUIRED` | An entry omits an explicit scope boundary. |
| `THREAT_PRECONDITIONS_REQUIRED` / `THREAT_IMPACT_REQUIRED` | A threat omits required bounded context. |

Diagnostics are stable, bounded, machine-readable evidence. They are not findings, approvals, or risk decisions.

## CCA-130 module and profile resolution

`validateCapabilityModuleCatalog` strict-decodes and schema-validates exact property, attacker, threat, and module-catalog bytes, then applies CCA-120 semantics, module semantics, and exact binding verification. `resolveProfile` additionally strict-decodes/schema-validates an exact request, verifies its exact module-catalog binding, and returns either bounded diagnostics with no profile or a deterministic resolved profile plus its encoded bytes. `validateResolvedProfile` re-resolves exact inputs and accepts only the exact deterministic byte sequence.

Module validation covers `module.<domain>.<name>` syntax, map-key/ID equality, per-class selection bounds/uniqueness/targets, self/duplicate/dangling/cyclic dependencies, available/unsupported discrimination, canonical unique conflict pairs, intrinsic dependency-closure conflicts, and the data-only safety boundary. Catalog and request bindings compare contract ID, catalog ID, catalog version, and SHA-256 of original bytes.

Resolution normalizes request order, expands module dependencies, preserves literal `unknown` and `unsupported`, applies conflicts without selecting a winner, propagates `unresolvable`, combines selections only from `resolved` modules, expands property dependencies, includes attacker/threat capability relations and threat-affected properties, and never infers attacker models from threats. Every selection retains source-module/inclusion-reason pairs; assumptions and exclusions retain source module IDs.

Serialization uses UTF-8, two spaces, LF, one final newline, fixed field order, sorted maps, and sorted set-like arrays. Diagnostics are capped at 256 and sorted by code/path. Profile resolution carries no execution, evidence, provenance, approval, certification, product-security, or release authority.

## CCA-240 evidence contracts

`evidence.ts` validates the four CCA-240 contracts and exports a caller-fact-only
`assessFreshness` function plus deterministic serializers. The pure assessor uses
the fixed `not-assessed` -> `mismatched` -> `stale` -> `unknown` -> `fresh`
decision order. It reads no current time, network, mutable revision, environment,
or external authority. Callers provide `asOf`, comparison bytes/fingerprints,
clock trust when selected, lifecycle applicability, and bounded authority IDs.

CCA-240 caps exact inputs and artifact references at 64, private opaque references
at the same 64-artifact ceiling, and diagnostics at 256. Semantic diagnostics are
deduplicated and sorted by code/path/message. Generated JSON is byte-stable for
identical semantic inputs; external bytes are always hashed as supplied.

The module does not implement evidence sufficiency, claim satisfaction, human
approval, certification, risk acceptance, release authority, private sidecars or
storage, HMAC/encryption, credentials, an upstream adapter, or a compatibility
claim. `pass` is not evidence-requirement satisfaction, `fresh` is not
sufficiency, and a binding set is not evidence storage.
