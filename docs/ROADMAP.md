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

- frozen bootstrap preservation plus separate manifest, lock, and evidence-backed compatibility-record contracts;
- explicit exact-byte content binding, source/producer/resolver identity, and fail-closed contract migration rules;
- security property, threat, and attacker vocabularies through three separate closed catalog contracts, stable identifiers, bounded relationships, public-safe catalog data, and explicit coverage review evidence;
- exact-bound capability module catalog, explicit profile request, and deterministic resolved-profile contracts; evidence-result contracts remain separate;
- separate CCA-240 execution/provenance/freshness/binding contracts using the closed status vocabulary and exact-byte composition;
- compatibility and contract-version negotiation rules.

This phase does not implement cryptographic primitives or protocols.

## Phase 2 — integration packs

Candidate work:

- future ae-framework bridge inputs and public synthetic fixtures, without a compatibility claim until separately validated;
- future GenAI Repo Auditor bridge inputs and target templates, without a compatibility claim until separately validated;
- public mapping suites that do not call either external system during unit
  tests.

The upstream repositories remain independently governed and are not modified from
this repository.

## Phase 3 — content-bound adapters and bridges

Candidate work:

- deterministic transformations between versioned contracts;
- bridge preservation of CCA-240 exact artifact/provenance bindings;
- private storage/sidecar design that preserves the CCA-240 public opaque boundary;
- bridge preservation of literal failure, timeout, unsupported, and tool-error states.

No adapter may turn tool evidence into human approval.

## Deferred release work

A release workflow, signing procedure, tag governance, checksums, SBOM, and artifact
attestation are intentionally deferred. No tag ruleset or publication automation
should be created until those procedures are reviewed and tested.
