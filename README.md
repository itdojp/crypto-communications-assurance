# Cryptographic Communications Assurance

Reusable, machine-readable assurance contracts, profiles, audit targets, and evidence bridges for cryptographic communication products.

The project is intended to integrate with:

- [ae-framework](https://github.com/itdojp/ae-framework) for specifications, assurance evidence, policy gates, and release judgments.
- [GenAI Repo Auditor](https://github.com/itdojp/genai-repo-auditor) for defensive repository security auditing.

## Project role

This repository provides domain-specific assurance inputs and integration contracts for cryptographic communication products. It is not a third assurance control plane.

Planned capabilities include:

- cryptographic-communications security property, threat, and attacker catalogs;
- evidence requirements and reusable capability modules;
- ae-framework-compatible assurance profiles and security artifacts;
- GenAI Repo Auditor-compatible audit packs and target templates;
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
