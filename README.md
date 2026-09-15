# Cryptographic Communications Assurance

Reusable, machine-readable assurance contracts, profiles, audit targets, and evidence bridges for cryptographic communication products.

Future, separately authorized bridge work may integrate with:

- [ae-framework](https://github.com/itdojp/ae-framework) for specifications, assurance evidence, policy gates, and release judgments.
- [GenAI Repo Auditor](https://github.com/itdojp/genai-repo-auditor) for defensive repository security auditing.

## Project role

This repository provides domain-specific assurance inputs and integration contracts for cryptographic communication products. It is not a third assurance control plane.

Planned capabilities include:

- cryptographic-communications security property, threat, and attacker catalogs;
- evidence requirements and reusable capability modules;
- tool-neutral assurance profiles and security artifacts that later bridges may map;
- repository-audit packs and target templates whose upstream mappings remain future work;
- content-bound evidence bridges between development assurance and repository auditing;
- deterministic synthetic fixtures and compatibility tests.

## Status

Bootstrap / pre-alpha.

No stable contract, compatibility commitment, production-readiness claim, or certification claim exists yet.

The frozen bootstrap contract remains the closed, data-only
[`cryptocomm-pack/v1`](schema/cryptocomm-pack-v1.schema.json) envelope. Its
`planned` value remains intent only and is not reinterpreted as compatibility.

CCA-110 adds three separate closed Draft 2020-12 contracts:

- [`cryptocomm-pack-manifest/v1`](schema/cryptocomm-pack-manifest-v1.schema.json) for a publisher/source declaration of one immutable pack;
- [`cryptocomm-pack-lock/v1`](schema/cryptocomm-pack-lock-v1.schema.json) for a consumer resolution of exact manifest bytes and resolver identity;
- [`cryptocomm-compatibility-record/v1`](schema/cryptocomm-compatibility-record-v1.schema.json) for an evidence-bound assessment of one exact manifest against one exact target.

These contracts do not contain a complete security property, threat, module, or integration catalog, and they make no actual compatibility claim about ae-framework or GenAI Repo Auditor. See [contract versioning](docs/CONTRACT_VERSIONING.md) and [ADR 0002](docs/decisions/0002-pack-manifest-lock-and-compatibility.md).

Contract inputs use bounded strict UTF-8 JSON decoding before schema and semantic validation. SHA-256 continues to cover the exact original bytes; no JSON canonicalization is implied.

CCA-120 adds three closed, protocol-neutral catalog contracts and proposed public catalog artifacts:

- [`cryptocomm-property-catalog/v1`](schema/cryptocomm-property-catalog-v1.schema.json): 40 security, privacy, recovery, resilience, and publication outcomes;
- [`cryptocomm-attacker-catalog/v1`](schema/cryptocomm-attacker-catalog-v1.schema.json): 28 attacker capabilities and 8 bounded attacker models;
- [`cryptocomm-threat-catalog/v1`](schema/cryptocomm-threat-catalog-v1.schema.json): 36 adverse events or paths that reference capabilities and affected properties.

The [human-readable](docs/CATALOG_COVERAGE.md) and [machine-readable](pack/catalogs/v1/coverage-matrix.json) coverage matrices expose the bounded Issue scope for review. They are not a catalog-set contract, registry, product claim, security proof, or completeness claim. See [ADR 0003](docs/decisions/0003-security-catalog-separation-and-relationships.md) and the [terminology source baseline](docs/SOURCE_BASELINE.md).

CCA-130 adds three closed contracts, a 15-entry public protocol-neutral module catalog, and a pure deterministic resolver:

- [`cryptocomm-capability-module-catalog/v1`](schema/cryptocomm-capability-module-catalog-v1.schema.json) defines available or unsupported reusable assurance-scope modules and exact-byte bindings to all three CCA-120 catalogs;
- [`cryptocomm-profile-request/v1`](schema/cryptocomm-profile-request-v1.schema.json) records an explicit module selection and exact module-catalog binding;
- [`cryptocomm-resolved-profile/v1`](schema/cryptocomm-resolved-profile-v1.schema.json) records literal module outcomes, catalog closure, source-module inclusion reasons, and source-attributed assumptions and exclusions.

The resolver validates exact bytes and bindings, expands module/property dependencies, detects conflicts without precedence, preserves `resolved`, `unknown`, `unsupported`, and `unresolvable`, and emits byte-stable UTF-8 JSON. `complete` and `incomplete` are resolution states only. The module catalog creates no default, recommendation, strongest profile, product claim, execution request, evidence result, or approval. See [ADR 0004](docs/decisions/0004-capability-modules-and-deterministic-profile-resolution.md).

The CCA-130 boundaries are explicit: `module != attacker capability`, `module != product capability`, `profile request != approval`, `resolved profile != product claim`, `resolution outcome != evidence status`, and `complete resolution != product security`.

CCA-240 adds four closed contracts and a pure, deterministic repository-local
freshness assessor:

- [`cryptocomm-execution-result/v1`](schema/cryptocomm-execution-result-v1.schema.json) preserves `pass`, `fail`, `skip`, `unsupported`, `timeout`, `tool-error`, and `not-run` with status-specific occurrence and artifact-role rules;
- [`cryptocomm-evidence-provenance/v1`](schema/cryptocomm-evidence-provenance-v1.schema.json) binds explicit subject forms, exact input bytes, producer/tool/environment/scope facts, evidence origin/use restriction, and public-content or private-opaque artifacts;
- [`cryptocomm-freshness-assessment/v1`](schema/cryptocomm-freshness-assessment-v1.schema.json) preserves `fresh`, `stale`, `mismatched`, `unknown`, and `not-assessed` from explicit caller facts only;
- [`cryptocomm-evidence-binding-set/v1`](schema/cryptocomm-evidence-binding-set-v1.schema.json) binds exact bytes of one result, provenance record, and always-present freshness assessment.

The binding set is a minimal composition root, not evidence storage or an
aggregate decision. See [CCA-240 contract semantics](docs/EVIDENCE_CONTRACTS.md)
and [ADR 0005](docs/decisions/0005-execution-provenance-freshness-and-binding.md).
CCA-240 makes no ae-framework or GenAI Repo Auditor compatibility claim and adds
no upstream adapter.

CCA-210 adds one closed
[`cryptocomm-ae-render-plan/v1`](schema/cryptocomm-ae-render-plan-v1.schema.json)
contract plus separate pure validation and rendering functions. The plan is the
operator-reviewed semantic authority for explicit property/claim,
threat/STRIDE/CWE, evidence-lane/kind, Context Pack reference, scope,
trust-boundary, output-disposition, and audit-tree-loss decisions. The renderer
may emit only `assurance-profile/v1`, `security-claim/v1`,
`security-threat-model/v1`, and `security-audit-scope/v1`.

Offline shape validation uses only the five schema byte sequences copied from
`itdojp/ae-framework@c5da6115638fdbfeebbc458b39fa6916db66afb0`, tree
`0d69865b37a4476a20f0f1f1f42031967d3ec3a7`, with exact digests and license
handling recorded in [`UPSTREAM.json`](integrations/ae-framework/pins/c5da6115638fdbfeebbc458b39fa6916db66afb0/UPSTREAM.json).
Tests do not fetch or execute ae-framework. Existing Context Packs are supplied
as exact-byte-bound references only. CCA-240 records bind representative
synthetic render inputs and generated bytes; their `pass` means only that the
transformation and exact pinned-schema validation succeeded.

The current native threat model emits `STRIDE` as its sole framework label while
retaining the operator-selected `CWE-200`, `CWE-345`, and `CWE-522` values on
their exact threat entries. The pinned schema does not bind a dated CWE Top 25
membership set, so CCA-210 records this general-CWE/framework limitation as an
informational projection loss rather than emitting `CWE_TOP_25`. A future Top 25
assertion requires an exact dated edition, exact membership data, validation,
and a separate accountable-human decision.

The CCA-210 boundaries are explicit: `property != product claim`,
`generated native claim != satisfied claim`,
`shape-valid != semantically compatible`,
`pass render != evidence satisfied`,
`Context Pack reference != Context Pack synthesis`,
`full commit in native audit scope != full CCA target identity`,
`explicit STRIDE/CWE mapping != automated threat classification`,
`renderer != ae-framework execution`, and
`pinned schema conformance != product-wide compatibility`. See
[ADR 0006](docs/decisions/0006-cca-owned-render-plan-and-pinned-ae-native-projection.md).

## Non-goals

This project does not:

- implement cryptographic primitives or protocols;
- certify products;
- prove the absence of vulnerabilities;
- confirm vulnerabilities without human security review;
- scan or exploit production or staging systems;
- automatically approve merges, releases, risk acceptance, or disclosure;
- store production secrets, customer data, or raw private audit evidence.

## Assurance boundary

Tool, model, scanner, test, and formal-verification outputs are evidence producers. They are not human approval or release authority.

Synthetic and test-only evidence must not be promoted to real evidence. An unexecuted, skipped, unsupported, timed-out, or failed check must not be represented as a pass.

Execution, provenance, freshness, and policy authority remain separate: `pass != evidence requirement satisfied`, `real != fresh`, `policy-evaluable != policy satisfied`, `fresh != sufficient`, and `evidence result != human approval`.

The normative boundaries are documented in:

- [Product boundary](docs/PRODUCT_BOUNDARY.md)
- [Public/private boundary](docs/PUBLIC_PRIVATE_BOUNDARY.md)
- [Status semantics](docs/STATUS_SEMANTICS.md)
- [Architecture](docs/ARCHITECTURE.md)

## Development baseline

- Node.js `>=22 <23` (the bootstrap pins `22.22.2` in `.node-version`);
- pnpm `10.34.5`, selected through Corepack and pinned by `packageManager`;
- TypeScript `5.9.3`;
- JSON Schema Draft 2020-12 and AJV `8.20.0`;
- Vitest `4.1.10`.

Install the exact dependency graph:

```bash
corepack enable
pnpm install --frozen-lockfile
```

Repository-local commands:

```bash
pnpm run build
pnpm run typecheck
pnpm run lint
pnpm run test
pnpm run check:schemas
pnpm run check:docs
pnpm run lint:workflows
pnpm run verify
```

`pnpm run verify` aggregates deterministic, repository-local build, type, lint,
schema, test, documentation, and workflow-policy checks. None of these commands
contacts an external model, scanner, registry fallback, or live target after the
locked dependencies have been installed.

## Workspace

The bootstrap layout reserves distinct areas for authoritative pack data,
contracts, later adapters, synthetic fixtures, examples, schemas, and tests.
Placeholder directories contain a README explaining their deferred scope; they
must not be interpreted as implemented integrations.

See [Architecture](docs/ARCHITECTURE.md) and [Roadmap](docs/ROADMAP.md).

## Contributing and security

Use an Issue, a dedicated branch, and a Draft PR as described in
[CONTRIBUTING.md](CONTRIBUTING.md). Report suspected vulnerabilities through
[GitHub private vulnerability reporting](SECURITY.md); do not place secrets or
private evidence in a public Issue.

## License

Apache License 2.0. See [LICENSE](LICENSE).

Attribution information is in [NOTICE](NOTICE), and repository-wide licensing
annotations are in [REUSE.toml](REUSE.toml).
