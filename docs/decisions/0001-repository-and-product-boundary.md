# ADR 0001: Repository and product boundary

- Status: Accepted for bootstrap
- Date: 2026-07-25
- Decision owners: accountable human maintainers

## Context

Cryptographic communication products need reusable assurance contracts that can be
consumed by existing development-assurance and repository-audit systems. Combining
domain content, orchestration, tool execution, evidence storage, and release
authority in another control plane would duplicate responsibilities and create an
unclear approval boundary.

The initial repository also needs a machine-readable artifact that can evolve
without claiming a complete security catalog or working integration.

## Decision

1. This repository is a data-first provider of contracts, schemas, assurance packs,
   audit inputs, synthetic fixtures, and later deterministic adapters.
2. It is not a third assurance control plane. ae-framework, GenAI Repo Auditor, and
   accountable human maintainers retain their respective responsibilities.
3. JSON is authoritative for machine contracts; Markdown is explanatory or a
   review surface.
4. The bootstrap schema is closed, Draft 2020-12, source-revision-bound, and uses
   bounded repository-relative artifact paths with SHA-256 digests.
5. Bootstrap artifacts are non-executable, require no network, and permit no
   secrets.
6. Automated evidence never conveys human approval. Synthetic evidence is never
   promoted to real evidence, and unexecuted checks are never represented as pass.
7. Cryptographic primitive and protocol implementation, live probing, external
   scanner/model dependencies, release, and publication are outside the boundary.

## Consequences

- The repository can validate a minimal pack envelope without implementing the
  eventual property, threat, capability, or integration catalogs.
- Integration directories initially contain boundary documentation rather than
  implementations; their existence is not a compatibility claim.
- Later executable tooling or private evidence references require new threat,
  authority, data-flow, and versioning decisions.
- A breaking interpretation of the bootstrap schema requires a new schema version.
- Human maintainers remain necessary for merge, risk, disclosure, and release
  decisions even when every automated check passes.

## Alternatives rejected

- **Build a third orchestration/control plane:** rejected because it duplicates
  existing systems and obscures authority.
- **Use Markdown as the machine contract:** rejected because deterministic closed
  validation and content binding would be weak.
- **Add a complete cryptographic assurance catalog during bootstrap:** rejected as
  an unreviewable scope expansion.
- **Allow networked tests for early integration confidence:** rejected because it
  makes verification non-deterministic and risks external or private targets.
