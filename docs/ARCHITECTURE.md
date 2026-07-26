# Architecture

## Design principles

1. **Data first.** JSON artifacts are authoritative. Markdown explains contracts
   and provides a human review surface; it is not a second machine authority.
2. **Closed versioned contracts.** Draft 2020-12 schemas reject undeclared fields
   and unsafe values instead of silently accepting them. The bootstrap meaning stays
   frozen while manifest, lock, and compatibility use distinct contract IDs.
3. **Content binding.** Pack declarations identify their source revision and bind
   artifact bytes with SHA-256 digests.
4. **No execution authority.** The bootstrap envelope is non-executable, requires
   no network, permits no secrets, and communicates no human approval.
5. **Deterministic local validation.** After locked dependency installation,
   build, schema, test, documentation, and workflow checks use repository data only.
6. **Adapter isolation.** Later integration-specific transformations stay outside
   authoritative domain contracts and preserve source content bindings.

## Repository areas

| Path | Bootstrap responsibility |
| --- | --- |
| `pack/` | Reserved root for later authoritative pack data. |
| `packages/contracts/` | TypeScript validation helpers for shared contracts. |
| `packages/cli/` | Reserved for a later local, non-authoritative CLI. |
| `packages/bridge/` | Reserved for later content-bound bridge logic. |
| `packages/ae-pack/` | Reserved for later ae-framework-compatible pack material. |
| `packages/gra-pack/` | Reserved for later GenAI Repo Auditor-compatible pack material. |
| `integrations/` | Integration documentation and, later, boundary-specific inputs. |
| `adapters/contracts/` | Reserved for versioned adapter input/output contracts. |
| `fixtures/` | Explicitly synthetic positive and negative test inputs. |
| `examples/` | Non-normative, synthetic usage examples. |
| `schema/` | Authoritative JSON Schema contracts. |
| `docs/` | Architecture, boundaries, semantics, roadmap, and decisions. |
| `tests/` | Deterministic repository-local behavior checks. |

Directories without bootstrap implementation contain an explanatory README. Their
presence does not claim that a bridge, adapter, compatibility layer, or property
catalog is implemented.

## Contract validation flow

1. A bounded strict decoder accepts no more than 1,048,576 exact bytes per manifest, lock, or compatibility record. It requires fatal UTF-8 and strict JSON, rejects comments, trailing commas, trailing data, and duplicate decoded member names at every nesting level, and requires an object root.
2. A caller validates only the object produced by that decoder against its checked-in closed Draft 2020-12 schema. `packages/contracts` compiles strict AJV 2020 validators without format or remote-schema loading.
3. After schema success, a separate pure semantic validator receives the same exact manifest, lock, and compatibility-record bytes and strict-decodes every object it inspects from those bytes. A separately mutated object therefore cannot be assessed under another byte digest.
4. Manifest/lock validation recomputes SHA-256 over the original exact manifest bytes and compares pack ID, pack version, source identity, and implementation identity.
5. Compatibility validation binds exact subject and target identities, record bytes, and required evidence references. A lock may contain at most one record for each exact subject/target pair; multiple supporting results belong in one record's evidence map.
6. Both validation layers return deterministic local results. Neither fetches a URL, resolves an arbitrary path, executes an artifact, contacts an integration, or promotes evidence into approval.

The authority boundaries are intentionally non-equivalent:

- `bootstrap envelope != manifest`
- `manifest != lock`
- `lock != compatibility record`
- `compatibility != human approval`
- `schema validation != semantic validation`
- `content binding != security proof`

SHA-256 covers the original exact bytes. JSON whitespace, member order, encoding, and line endings therefore affect content identity; strict decoding does not rewrite input and version 1 performs no implicit JSON canonicalization. A manifest has no self-digest.

## Trust boundaries

- **Public repository boundary:** schemas, source, documentation, and explicitly
  synthetic fixtures may be committed after review.
- **Private evidence boundary:** secrets, customer data, raw findings, production
  evidence, and restricted reports remain outside Git history.
- **Tool boundary:** a tool emits evidence with a literal status; it does not make a
  human decision.
- **Integration boundary:** ae-framework and GenAI Repo Auditor remain independent
  systems. No code in this bootstrap calls or modifies them.

See [`PUBLIC_PRIVATE_BOUNDARY.md`](PUBLIC_PRIVATE_BOUNDARY.md) and
[`STATUS_SEMANTICS.md`](STATUS_SEMANTICS.md).

## Compatibility and evolution

`cryptocomm-pack/v1` is a frozen bootstrap envelope. Its `planned` value states intent only. The CCA-110 validation layer accepts exactly one legacy migration pair, `planned` to `unknown`; all other combinations involving legacy `planned`, `compatible`, or `unsupported` and any new state fail closed. It performs no evidence-enriching migration. CCA-110 uses a separate compatibility record with `unknown`, `compatible`, `incompatible`, and `unsupported` states.

`compatible` and `incompatible` require exact subject/target identity and content-addressed evidence. `unsupported` requires a bounded reason and scope. `unknown` makes no compatibility claim. Evidence map keys are bounded bundle-relative identifiers only: they are not repository authorities, network locators, private paths, local absolute paths, or provenance records. Provenance, access control, retention, correlation risk, and freshness remain deferred to CCA-240. No state communicates human approval, release approval, certification, production readiness, protocol security, or vulnerability absence.

Each `schemaVersion` has one immutable meaning. Breaking changes require a new contract ID/version; migration is explicit, deterministic, tested, and fail-closed. See [`CONTRACT_VERSIONING.md`](CONTRACT_VERSIONING.md).
