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

## CCA-110 contract layer

CCA-110 does not alter the bootstrap envelope. It adds:

- a manifest that separates source-tree identity, producer identity, and path-keyed exact-byte artifact declarations;
- a lock that binds exact manifest bytes, the same manifest source identity, resolver implementation identity, and optional compatibility-record references;
- a compatibility record that binds an exact manifest subject to an exact generic target implementation/contract identity.

The lock does not duplicate compatibility state as an independent authority and may bind at most one record per exact subject/target pair. Evidence keys are bundle-relative identifiers, not locations or provenance. The compatibility record does not grant approval. All three contracts preserve `executable=false`, `networkRequired=false`, and `secretsAllowed=false`.

## CCA-120 catalog layer

CCA-120 adds separate property, attacker, and threat catalogs. Properties describe scoped outcomes; capabilities describe attacker operations or access conditions; attacker models compose capabilities with explicit assumptions and exclusions; threats connect capabilities and preconditions to affected properties and bounded impact statements.

Catalog entries are data and terminology. They are not controls, product claims, evidence results, human decisions, vulnerability confirmations, certifications, or universal requirements. Abstract required-evidence kinds identify expected evidence lanes only; they do not carry execution status, provenance, freshness, approval, or release meaning.

The catalog artifacts repeat no source or producer identity. CCA-110 manifest and lock contracts remain the packaging and exact-byte identity authority. No fourth catalog-set or registry contract is introduced.

## CCA-130 module and profile layer

CCA-130 adds a module catalog, explicit profile request, and deterministic resolved profile. A module groups CCA-120 assurance-scope selections with dependencies, assumptions, and exclusions. It is neither an attacker capability nor a product capability. The module catalog and request bind exact upstream bytes; they do not repeat CCA-110 source or producer identity.

Resolution can be `complete` or `incomplete`, while individual modules remain `resolved`, `unknown`, `unsupported`, or `unresolvable`. These outcomes record composition only. A profile request is not approval; a resolved profile is not a product claim; a resolution outcome is not an evidence status; complete resolution is not product security. The resolver does not execute checks, assess product satisfaction, select a conflict winner, infer attacker models from threats, approve risk, or authorize publication/release.

CCA-130 contains no CCA-240 execution status, evidence result/class, provenance, freshness, retention, access-control, or approval fields. Its unsupported private-provenance module makes that deferral visible without widening the product boundary.

## CCA-240 evidence contract layer

CCA-240 adds separate execution-result, evidence-provenance,
freshness-assessment, and exact-byte binding-set contracts. It records facts about
one declared check, explicit subject/input/producer/tool/environment/scope
identity, public-content or private-opaque artifact references, and a reproducible
freshness comparison from caller facts.

The layer does not decide that a CCA-120 evidence lane or product claim is
satisfied. `real` is not `fresh`; `policy-evaluable` is not policy-satisfied;
`fresh` is not sufficient; a result is not human approval; and the binding set is
not evidence storage. No private storage/sidecar, HMAC/encryption, credential,
policy/approval/release contract, upstream adapter, CLI, live probe, or
cryptographic implementation is introduced.

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
