# ADR 0002: Pack manifest, lock, and compatibility separation

- Status: Proposed for CCA-110 review
- Date: 2026-07-26
- Decision owners: accountable human maintainers

## Context

The frozen `cryptocomm-pack/v1` bootstrap envelope combines a minimal pack declaration with placeholder compatibility intent. CCA-110 needs deterministic publisher, consumer-resolution, and compatibility-assessment artifacts without reinterpreting that bootstrap contract or creating self-reference, execution authority, or a compatibility claim about ae-framework or GenAI Repo Auditor.

## Decision

### Separate contracts

Add three closed JSON Schema Draft 2020-12 contracts:

1. `cryptocomm-pack-manifest/v1` is the publisher/source declaration for one immutable pack and its path-keyed, exact-byte artifact bindings.
2. `cryptocomm-pack-lock/v1` is a consumer resolution of one exact manifest. It binds manifest bytes, manifest source identity, resolver implementation identity, and optional exact compatibility-record references.
3. `cryptocomm-compatibility-record/v1` assesses one exact manifest subject against one exact target implementation and contract.

The lock repeats compatibility subject and target identities only to bind a referenced record. It does not carry an independent compatibility state. One lock may reference at most one record for each exact subject/target pair. Multiple supporting results belong inside that record's evidence map; v1 defines no precedence, latest selection, history, producer-specific aggregation, or conflict resolution.

### Identity model

- Manifest source identity consists of a stable provider-scoped repository ID, exact Git commit object identity, and exact Git tree object identity.
- The source revision identifies the source tree being packaged; it is not inferred from the commit that stores generated manifest bytes.
- Producer, resolver, and target implementation identities contain a stable implementation ID, version, source repository ID, and exact source revision.
- Target contract identity remains generic and data-only, so later ae-framework and GenAI Repo Auditor adapters need no live API call.
- Normative identity excludes branches, wall-clock timestamps, run IDs, local paths, hostnames, tokens, credentials, and generated approval fields.

### Content identity

Manifest artifact declarations are keyed by bounded repository-relative POSIX paths and contain SHA-256, media type, bounded artifact role, and contract identity where applicable. SHA-256 is computed over exact bytes. Version 1 introduces no implicit JSON canonicalization.

A manifest has no self-digest. A lock externally binds the exact manifest bytes. Compatibility records and lock references content-bind exact evidence or record bytes. Evidence map keys are bounded bundle-relative identifiers only. They confer no repository authority and are not network locators, private evidence paths, local absolute paths, or provenance records. Evidence provenance, access control, retention, correlation risk, and freshness are deferred to CCA-240.

### Compatibility states

- `unknown`: no compatibility claim and no evidence-based positive or negative assessment.
- `compatible`: exact subject and target plus one or more content-addressed evidence references.
- `incompatible`: exact subject and target plus one or more content-addressed evidence references.
- `unsupported`: exact subject and target plus an explicit bounded reason and scope.

No state means human approval, merge approval, release approval, certification, production readiness, protocol security, or vulnerability absence. The CCA-110 validator accepts only legacy `planned` to new `unknown`; it rejects every other combination involving legacy `planned`, `compatible`, or `unsupported`. It is not an evidence-enriching migration transformer.

### Validation layers

Generic AJV schema compilation remains separate from pure semantic validation. Before either layer, a strict decoder applies a 1,048,576-byte and 128-container nesting limit per artifact, fatal UTF-8 decoding, strict JSON syntax, decoded-member uniqueness at every nesting level, and an object-root requirement. It rejects comments, trailing commas, and trailing data. A non-recursive structural preflight bounds nesting before parsing, and duplicate-member traversal is non-recursive. Duplicate members fail before schema or semantic validation, including duplicates expressed using JSON escapes.

After a caller schema-validates the strict-decoded value, semantic validators receive the same exact manifest, lock, and compatibility-record bytes. Every object they inspect is derived from those bytes so that a digest cannot be paired with a separately mutated object. The original bytes remain the SHA-256 input; the decoder performs no canonicalization. The validators do not fetch, clone, resolve arbitrary paths, execute artifacts, contact upstream tools, or call an external model/scanner.

Bounded diagnostics cover strict decoding, exact-byte manifest and record digests, pack ID/version, source identity, implementation identity, compatibility subject/target and pair uniqueness, evidence requirements, and forbidden legacy status migration.

### Versioning

Every `schemaVersion` has one immutable meaning. Breaking changes require a new contract ID/version. Migration is explicit, deterministic, tested, and fail-closed; there is no in-place reinterpretation.

## Consequences

- Publisher intent, consumer resolution, and compatibility assessment can evolve independently without authority confusion.
- Exact-byte digests make whitespace and encoding part of identity; producers must preserve the bytes that consumers lock.
- Committed examples use synthetic repository, revision, target, and evidence identities and make no upstream compatibility claim.
- Schema validation and semantic validation produce machine evidence only; human review remains required.
- Private evidence handling and provenance, operational timestamps, compatibility history or aggregation, live probing, a CLI, release behavior, and upstream modifications remain outside CCA-110.

## Alternatives rejected

- Reinterpret `cryptocomm-pack/v1`: rejected because it would change a frozen bootstrap meaning.
- Put manifest, lock, and compatibility state in one artifact: rejected because it conflates publisher, resolver, and assessment authority.
- Add a manifest self-digest: rejected because it creates a self-reference problem.
- Canonicalize JSON implicitly: rejected because version 1 requires transparent exact-byte identity.
- Probe upstream tools during tests: rejected because it would introduce network, trust, and nondeterminism outside Issue scope.
- Add a contract registry: deferred because three explicit schema IDs already provide deterministic mapping without a new meta-framework.
