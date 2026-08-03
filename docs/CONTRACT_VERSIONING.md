# Contract versioning and migration

## Contract inventory

| `schemaVersion` | Role | Evolution status |
| --- | --- | --- |
| `cryptocomm-pack/v1` | Frozen bootstrap envelope | Its existing meaning is immutable; `planned` remains intent only. |
| `cryptocomm-pack-manifest/v1` | Publisher/source declaration for one immutable pack | New CCA-110 contract. |
| `cryptocomm-pack-lock/v1` | Consumer resolution of exact manifest bytes and resolver identity | New CCA-110 contract. |
| `cryptocomm-compatibility-record/v1` | Evidence-backed assessment of an exact subject against an exact target | CCA-110 contract. |
| `cryptocomm-property-catalog/v1` | Stable protocol-neutral property entries and bounded dependencies/evidence needs | Proposed CCA-120 contract. |
| `cryptocomm-attacker-catalog/v1` | Separate capability and bounded attacker-model entries | Proposed CCA-120 contract. |
| `cryptocomm-threat-catalog/v1` | Threat entries relating capabilities, preconditions, affected properties, and impact | Proposed CCA-120 contract. |
| `cryptocomm-capability-module-catalog/v1` | Exact-bound available/unsupported assurance-scope modules, dependencies, and canonical conflicts | Proposed CCA-130 contract. |
| `cryptocomm-profile-request/v1` | Explicit module selection bound to exact module-catalog bytes | Proposed CCA-130 contract. |
| `cryptocomm-resolved-profile/v1` | Deterministic closure, literal module outcomes, and source traceability | Proposed CCA-130 contract. |
| `cryptocomm-execution-result/v1` | Literal status-discriminated execution/non-execution fact | CCA-240 v1 contract. |
| `cryptocomm-evidence-provenance/v1` | Exact execution binding, subject/input/producer/tool/environment/scope identity, classification, and artifact references | CCA-240 v1 contract. |
| `cryptocomm-freshness-assessment/v1` | Pure caller-fact freshness comparison | CCA-240 v1 contract. |
| `cryptocomm-evidence-binding-set/v1` | Minimal exact-byte composition root | CCA-240 v1 contract. |
| `cryptocomm-ae-render-plan/v1` | Exact-bound explicit semantic decisions for four pinned ae-framework-native projections | CCA-210 v1 contract. |

Each value identifies one closed JSON Schema Draft 2020-12 contract. The manifest, lock, and compatibility record have separate identities because their authorities and content bindings differ.

## Immutable meaning

- A `schemaVersion` value has exactly one meaning.
- A breaking semantic or validation change requires a new contract ID/version.
- A contract must not reinterpret an existing field, widen an authority boundary, or silently accept a previously invalid value in place.
- Documentation may clarify an existing meaning but must not become a second machine authority.
- Schema conformance is only schema conformance; it is not truth, completeness, compatibility, security, approval, certification, or release readiness.

Because these contracts are closed, even an apparently optional field can change the accepted document set. Such evolution requires an explicit review and versioning decision rather than an unreviewed in-place edit.

## Catalog identity evolution

CCA-120 map keys and entry `id` values are immutable semantic identities. A material change to a property, capability, attacker model, or threat meaning requires a new identifier or a new contract/catalog major version. Titles and definitions may be clarified only when the accepted meaning and relationship authority do not change.

The only v1 relationship authorities are property `dependsOn`, attacker `capabilities`, threat `capabilities`, and threat `affectedProperties`. Adding a new relationship or changing category meaning is a contract change, not an editorial update. Catalog source and producer identity remain in CCA-110 packaging rather than being added in place to catalog v1.

## Module and profile identity evolution

CCA-130 uses stable `module.<domain>.<name>` and `profile.<domain>.<name>` identifiers. A material change to a module's selections, dependency meaning, assumptions, exclusions, availability meaning, or unsupported scope requires a new module ID or a new contract/catalog major version. Adding conflict precedence or another relationship authority is a contract change, not an editorial update.

The module catalog binds exact CCA-120 contract/catalog identities and bytes. A request similarly binds exact module-catalog identity and bytes. A resolved profile repeats the four bindings actually used; it does not repeat CCA-110 source/producer fields or carry the raw request-byte digest. Editing whitespace or member order in an input changes its digest even when it strict-decodes to equivalent JSON.

Resolved-profile serialization is part of the v1 contract behavior: UTF-8, two spaces, LF, one final newline, fixed field order, sorted maps, and sorted set-like arrays. Changing output ordering, closure rules, inclusion-reason meaning, or literal `resolved`/`unknown`/`unsupported`/`unresolvable` and `complete`/`incomplete` semantics requires explicit version review. These resolution outcomes must never be migrated implicitly into CCA-240 execution/evidence status.

## Evidence contract evolution

CCA-240 v1 keeps execution, provenance, freshness, and composition under separate
contract IDs. The seven execution states, three permitted origin/use pairs, three
subject forms, public/private artifact discrimination, five freshness states and
decision order, and exact three-record binding root are immutable v1 meanings.

A later contract must not silently promote non-execution to pass, synthetic to
real, test-only to policy-evaluable, freshness to sufficiency, scanner output to a
confirmed vulnerability, or any evidence to human approval/certification/release.
Adding private sidecars/storage, policy decisions, approval, satisfaction,
certification, risk acceptance, release authority, or upstream mappings requires
a new separately authorized contract/Issue rather than an optional v1 field.

## ae render-plan evolution

CCA-210 v1 has one CCA-owned contract. The upstream repository, commit, tree,
five schema paths/blob SHAs/exact-byte digests, four permitted output kinds,
property/claim and threat identity rules, dispositions, explicit native enums,
scope/tree-loss record, Context Pack reference-only boundary, safety constants,
and deterministic serializer behavior are part of its reviewed meaning.

The current threat-model projection emits only `STRIDE` in `frameworks` and
retains explicitly selected CWE IDs on individual threats. Future
`CWE_TOP_25` output requires an exact dated CWE Top 25 edition, exact membership
data, validation of every emitted CWE against that edition, and a separate
accountable-human decision; it is not an in-place v1 inference.

The tuple `cca-ae-renderer/v1@0.0.0`, the fixed source path, and the schema-fixed
source SHA-256 names the exact current renderer snapshot for this reviewed v1
boundary. After acceptance, a source change must not silently replace only that
digest under the same historical meaning. It requires a reviewed
implementation-identity, package-version, or render-plan contract-version
decision.

Changing the upstream pin, adding a native kind, following a mutable upstream
ref, synthesizing Context Packs, adding a render-result/output-index contract,
inferring a mapping, or introducing satisfaction/policy/approval/release fields
requires a separately authorized version decision. A later upstream schema with
the same apparent fields is not accepted automatically. Shape conformance to the
current exact bytes is not a compatibility migration.

Renderer output ordering is part of v1 behavior: UTF-8, two spaces, LF, one
final newline, fixed field order, and code-point-sorted set-like arrays/maps.
Optional `generatedAt`, summaries, and assurance-profile deployment/gate-policy
content are omitted. Exact output records remain the existing CCA-240 contracts;
their evolution is independent.

## Explicit migration

A migration is a separately reviewed deterministic transformation. Its specification must identify:

- exact source and destination contract IDs;
- exact input bytes or their content digest;
- deterministic output rules;
- bounded machine-readable failure diagnostics;
- information that cannot be represented without loss;
- validation for positive, negative, and ambiguous inputs;
- the human decision boundary retained after migration.

Ambiguous, lossy, unrecognized, or under-specified migrations fail closed. No validator in CCA-110 performs an implicit or evidence-enriching migration.

The current validator exposes only this fail-closed legacy-status relation:

| Legacy status | `unknown` | `compatible` | `incompatible` | `unsupported` |
| --- | --- | --- | --- | --- |
| `planned` | accepted | rejected | rejected | rejected |
| `compatible` | rejected | rejected | rejected | rejected |
| `unsupported` | rejected | rejected | rejected | rejected |

The only accepted pair is legacy `planned` to new `unknown`. Every other combination is rejected as `LEGACY_STATUS_MIGRATION_FORBIDDEN`. In particular, equal spelling does not supply the missing exact target, evidence, reason, scope, or provenance needed to migrate legacy `compatible` or `unsupported` into a new assessed state. A future migration requires its own versioned contract and review.

## Content binding across versions

SHA-256 values cover exact referenced bytes. JSON member order, whitespace, encoding, and line endings therefore affect a digest. Version 1 defines no implicit JSON canonicalization. Strict decoding validates, but does not rewrite, at most 1,048,576 bytes and 128 nested object/array containers per artifact. A manifest never contains its own digest; a lock binds the separately supplied manifest bytes.

## Human authority

Version selection, compatibility commitments, migration acceptance, risk acceptance, merge, release, and publication remain human decisions. Automation can validate declared contracts and content bindings but cannot approve them.
