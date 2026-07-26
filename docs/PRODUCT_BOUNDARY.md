# Product boundary

## Product role

Cryptographic Communications Assurance provides reusable, data-first assurance
packs for products that use cryptographic communications. Its deliverables are
machine-readable contracts, schemas, profiles, audit targets, synthetic fixtures,
and later adapters that other accountable systems can consume.

The intended integration surfaces are:

- **ae-framework** assurance inputs for specification, evidence, policy, and
  human-controlled release judgments;
- **GenAI Repo Auditor** defensive audit packs and target templates;
- deterministic repository-local validation of the data contracts shared with
  those systems.

This repository is not a third assurance control plane. It does not own product
release decisions, audit orchestration, scanner execution, vulnerability triage,
or approval state for either integration.

## Bootstrap deliverable

The bootstrap establishes a closed JSON Schema envelope for future pack artifacts.
It binds a pack declaration to a source revision and bounded repository-relative
artifact references with SHA-256 digests. The envelope is data only and requires:

- `executable=false`;
- `networkRequired=false`;
- `secretsAllowed=false`.

The bootstrap does not establish the eventual property, threat, attacker,
capability, module, or bridge catalogs. A `planned` compatibility declaration is
not proof of compatibility.

## Non-goals

The repository does not:

- implement a cryptographic primitive, cryptographic protocol, or custom
  cryptographic algorithm;
- certify a product or prove the absence of vulnerabilities;
- confirm a vulnerability without human security review;
- generate exploits or probe production, staging, or external hosts;
- treat AI, scanner, test, or formal-tool output as human approval;
- automatically merge, release, accept risk, publish, or disclose;
- store private customer material, production secrets, or raw audit evidence;
- modify or replace ae-framework or GenAI Repo Auditor.

## Decision authority

Contracts can describe evidence and compatibility. They cannot convey human
approval. Accountable human maintainers retain scope, merge, risk, release,
publication, and disclosure authority as defined in [`GOVERNANCE.md`](../GOVERNANCE.md).

Any later proposal to expand these boundaries requires its own Issue, explicit
threat and data-flow review, contract versioning decision, deterministic tests, and
human approval. It must not silently broaden the bootstrap schema.
