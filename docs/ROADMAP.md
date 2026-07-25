# Roadmap

Roadmap entries describe intent, not a delivery, compatibility, security, or release
commitment. Each phase requires a separately scoped Issue and human decision.

## Phase 0 — repository bootstrap

- establish immutable product and evidence boundaries;
- add the closed, data-only `cryptocomm-pack/v1` envelope;
- add deterministic valid and invalid synthetic fixture validation;
- establish Node.js, pnpm, TypeScript, JSON Schema, test, and CI baselines;
- create no release, package publication, live scan, or integration execution.

## Phase 1 — assurance domain contracts

Candidate work, subject to explicit contract design:

- security property, threat, and attacker vocabularies;
- evidence requirement and capability module contracts;
- result records using the closed status vocabulary;
- compatibility and contract-version negotiation rules.

This phase does not implement cryptographic primitives or protocols.

## Phase 2 — integration packs

Candidate work:

- ae-framework-compatible assurance inputs and public synthetic fixtures;
- GenAI Repo Auditor-compatible audit inputs and target templates;
- public compatibility suites that do not call either external system during unit
  tests.

The upstream repositories remain independently governed and are not modified from
this repository.

## Phase 3 — content-bound adapters and bridges

Candidate work:

- deterministic transformations between versioned contracts;
- artifact digest verification and provenance records;
- private evidence reference design that preserves the public/private boundary;
- explicit failure, timeout, unsupported, and tool-error propagation.

No adapter may turn tool evidence into human approval.

## Deferred release work

A release workflow, signing procedure, tag governance, checksums, SBOM, and artifact
attestation are intentionally deferred. No tag ruleset or publication automation
should be created until those procedures are reviewed and tested.
