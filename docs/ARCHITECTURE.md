# Architecture

## Design principles

1. **Data first.** JSON artifacts are authoritative. Markdown explains contracts
   and provides a human review surface; it is not a second machine authority.
2. **Closed versioned contracts.** Draft 2020-12 schemas reject undeclared fields
   and unsafe values instead of silently accepting them. The bootstrap meaning stays
   frozen while manifest, lock, and compatibility use distinct contract IDs.
3. **Content binding.** Pack declarations identify their source revision and bind
   artifact bytes with SHA-256 digests. Module catalogs and profile requests bind
   their exact declared inputs without duplicating source or producer identity.
4. **No execution authority.** The bootstrap envelope is non-executable, requires
   no network, permits no secrets, and communicates no human approval.
5. **Deterministic local validation.** After locked dependency installation,
   build, schema, test, documentation, and workflow checks use repository data only.
6. **Adapter isolation.** Later integration-specific transformations stay outside
   authoritative domain contracts and preserve source content bindings.

## Repository areas

| Path | Bootstrap responsibility |
| --- | --- |
| `pack/` | Authoritative JSON-first domain catalog data and a non-contract coverage review matrix. |
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

Directories without implementation contain an explanatory README. Their presence does not claim that a bridge, adapter, compatibility layer, CLI, or upstream integration is implemented. The three CCA-120 catalog files under `pack/catalogs/v1/` and the CCA-130 module catalog under `pack/modules/v1/` are authoritative public data; the adjacent CCA-120 coverage matrix is review evidence rather than a fourth contract.

## Contract validation flow

1. A bounded strict decoder accepts no more than 1,048,576 exact bytes and 128 nested object/array containers per manifest, lock, or compatibility record. It requires fatal UTF-8 and strict JSON, rejects comments, trailing commas, trailing data, and duplicate decoded member names at every nesting level, and requires an object root. Non-recursive structural and duplicate-member walks prevent nesting from becoming an unbounded call-stack input.
2. A caller validates only the object produced by that decoder against its checked-in closed Draft 2020-12 schema. `packages/contracts` compiles strict AJV 2020 validators without format or remote-schema loading.
3. After schema success, a separate pure semantic validator receives the same exact manifest, lock, and compatibility-record bytes and strict-decodes every object it inspects from those bytes. A separately mutated object therefore cannot be assessed under another byte digest.
4. Manifest/lock validation recomputes SHA-256 over the original exact manifest bytes and compares pack ID, pack version, source identity, and implementation identity.
5. Compatibility validation binds exact subject and target identities, record bytes, and required evidence references. A lock may contain at most one record for each exact subject/target pair; multiple supporting results belong in one record's evidence map.
6. Both validation layers return deterministic local results. Neither fetches a URL, resolves an arbitrary path, executes an artifact, contacts an integration, or promotes evidence into approval.

## Catalog validation flow

1. The same CCA-110 strict decoder derives each catalog object from no more than 1,048,576 exact UTF-8 bytes and rejects invalid syntax, excess nesting, and duplicate decoded member names before later validation.
2. A caller separately validates each object against its closed Draft 2020-12 schema.
3. Pure semantic validators enforce stable map-key/entry identity, domain agreement, bounded maps and references, explicit assumptions and exclusions, safety flags, and required category coverage.
4. Cross-catalog validation resolves property dependencies, attacker capability references, and threat capability/property references. It rejects self-dependencies, cycles, dangling references, unknown relationships, and duplicate semantic identifiers.
5. CCA-110 manifest validation independently verifies exact catalog-byte SHA-256 bindings. Catalog semantic validation neither hashes itself into a catalog nor duplicates source/producer identity.

Threat applicability to attacker models is derived through capability composition. Threat entries do not name attacker models as a second relationship authority. Property evidence kinds are abstract lanes, not execution results or approval.

## Profile resolution flow

1. The resolver strict-decodes the exact property, attacker, threat, module-catalog, and request byte sequences before schema or semantic use. It separately applies all five checked-in closed Draft 2020-12 schemas.
2. CCA-120 cross-catalog semantics are revalidated. The module catalog is checked for stable key/ID identity, bounded selections, selection targets, directed dependency integrity, canonical unique conflicts, intrinsic closure conflicts, and the data-only boundary.
3. SHA-256 is recomputed over the original catalog and module-catalog bytes. Contract ID, catalog ID, catalog version, and digest must all match each declared binding. Input is never canonicalized.
4. Requested module IDs are sorted, known dependency closures are expanded, and absent requested IDs remain `unknown`. Known unsupported entries remain `unsupported`.
5. When the selected closure contains a declared conflict, no winner or precedence is selected. Both sides and every available dependent become `unresolvable`.
6. Only `resolved` modules contribute direct catalog selections. Attacker capabilities and threat capabilities/affected properties are expanded, then every included property dependency is expanded transitively. Threats never infer attacker models.
7. Each selection records source-module/inclusion-reason pairs. Assumptions and exclusions retain source module IDs for all known visible modules and are not interpreted as facts, waivers, controls, or decisions.
8. A valid request always produces `complete` or `incomplete` output. Invalid JSON/contracts/semantics or any exact binding mismatch produces bounded deterministic diagnostics and no resolved profile.
9. Output is UTF-8 JSON with two-space indentation, LF, one final newline, fixed field order, lexicographically sorted maps, and sorted set-like arrays. No timestamp, run ID, hostname, local path, mutable branch, credential, request-byte digest, or generated approval is emitted.

The authority boundaries are intentionally non-equivalent:

- `bootstrap envelope != manifest`
- `manifest != lock`
- `lock != compatibility record`
- `compatibility != human approval`
- `schema validation != semantic validation`
- `content binding != security proof`
- `catalog entry != product claim`
- `catalog coverage != security proof`
- `threat != confirmed vulnerability`
- `attacker model != universal requirement`
- `evidence need != evidence result`
- `reference source != compliance claim`
- `module != attacker capability`
- `module != product capability`
- `profile request != approval`
- `resolved profile != product claim`
- `resolution outcome != evidence status`
- `complete resolution != product security`

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

CCA-130 module outcomes `resolved`, `unknown`, `unsupported`, and `unresolvable`, plus overall `complete` and `incomplete`, are a separate vocabulary from check execution/evidence status. They carry no CCA-240 provenance, freshness, retention, access, risk, approval, certification, or release semantics. A complete resolution proves only that deterministic expansion encountered no unresolved module outcome for the bound inputs.

Each `schemaVersion` has one immutable meaning. Breaking changes require a new contract ID/version; migration is explicit, deterministic, tested, and fail-closed. See [`CONTRACT_VERSIONING.md`](CONTRACT_VERSIONING.md).
