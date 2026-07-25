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

## License

Apache License 2.0. See [LICENSE](LICENSE).
