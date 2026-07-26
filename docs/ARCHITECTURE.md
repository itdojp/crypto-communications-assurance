# Architecture

## Design principles

1. **Data first.** JSON artifacts are authoritative. Markdown explains contracts
   and provides a human review surface; it is not a second machine authority.
2. **Closed bootstrap contract.** Draft 2020-12 schemas reject undeclared fields
   and unsafe values instead of silently accepting them.
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

## Bootstrap validation flow

1. A caller reads a candidate JSON pack and the checked-in Draft 2020-12 schema.
2. `packages/contracts` creates a strict AJV 2020 validator without format or
   remote-schema loading.
3. The validator returns a discriminated local result: valid with no errors, or
   invalid with AJV error objects.
4. Tests demonstrate that the valid synthetic fixture passes and the invalid
   fixture fails, including safety constants and repository-path constraints.

The validator does not fetch referenced artifacts, recompute their digests, execute
them, contact integrations, or promote results to approval. Those capabilities are
outside this bootstrap and require later contracts.

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

Compatibility declarations in the initial schema are explicit data fields. A
`planned` value states intent only. A later `compatible` claim requires a versioned
contract, fixtures derived from public or synthetic data, exact-head test evidence,
and human review. Breaking schema changes require a new schema version rather than
in-place reinterpretation.
