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

The lock repeats compatibility subject and target identities only to bind a referenced record. It does not carry an independent compatibility state.

### Identity model

- Manifest source identity consists of a stable provider-scoped repository ID, exact Git commit object identity, and exact Git tree object identity.
- The source revision identifies the source tree being packaged; it is not inferred from the commit that stores generated manifest bytes.
- Producer, resolver, and target implementation identities contain a stable implementation ID, version, source repository ID, and exact source revision.
- Target contract identity remains generic and data-only, so later ae-framework and GenAI Repo Auditor adapters need no live API call.
- Normative identity excludes branches, wall-clock timestamps, run IDs, local paths, hostnames, tokens, credentials, and generated approval fields.

### Content identity

Manifest artifact declarations are keyed by bounded repository-relative POSIX paths and contain SHA-256, media type, bounded artifact role, and contract identity where applicable. SHA-256 is computed over exact bytes. Version 1 introduces no implicit JSON canonicalization.

A manifest has no self-digest. A lock externally binds the exact manifest bytes. Compatibility records and lock references content-bind exact evidence or record bytes.

### Compatibility states

- `unknown`: no compatibility claim and no evidence-based positive or negative assessment.
- `compatible`: exact subject and target plus one or more content-addressed evidence references.
- `incompatible`: exact subject and target plus one or more content-addressed evidence references.
- `unsupported`: exact subject and target plus an explicit bounded reason and scope.

No state means human approval, merge approval, release approval, certification, production readiness, protocol security, or vulnerability absence. Legacy bootstrap `planned` may migrate only to `unknown`, or be rejected.

### Validation layers

Generic AJV schema compilation remains separate from pure semantic validation. After a caller schema-validates values decoded from the same exact bytes, semantic validators receive the parsed lock and exact manifest/compatibility-record bytes. They derive the manifest and record objects they inspect from those bytes so that a digest cannot be paired with a separately mutated object. They do not fetch, clone, resolve arbitrary paths, execute artifacts, contact upstream tools, or call an external model/scanner.

Bounded diagnostics cover exact-byte manifest and record digests, pack ID/version, source identity, implementation identity, compatibility subject/target, evidence requirements, and forbidden legacy status promotion.

### Versioning

Every `schemaVersion` has one immutable meaning. Breaking changes require a new contract ID/version. Migration is explicit, deterministic, tested, and fail-closed; there is no in-place reinterpretation.

## Consequences

- Publisher intent, consumer resolution, and compatibility assessment can evolve independently without authority confusion.
- Exact-byte digests make whitespace and encoding part of identity; producers must preserve the bytes that consumers lock.
- Committed examples use synthetic repository, revision, target, and evidence identities and make no upstream compatibility claim.
- Schema validation and semantic validation produce machine evidence only; human review remains required.
- Private evidence references, operational timestamps, live probing, a CLI, release behavior, and upstream modifications remain outside CCA-110.

## Alternatives rejected

- Reinterpret `cryptocomm-pack/v1`: rejected because it would change a frozen bootstrap meaning.
- Put manifest, lock, and compatibility state in one artifact: rejected because it conflates publisher, resolver, and assessment authority.
- Add a manifest self-digest: rejected because it creates a self-reference problem.
- Canonicalize JSON implicitly: rejected because version 1 requires transparent exact-byte identity.
- Probe upstream tools during tests: rejected because it would introduce network, trust, and nondeterminism outside Issue scope.
- Add a contract registry: deferred because three explicit schema IDs already provide deterministic mapping without a new meta-framework.
