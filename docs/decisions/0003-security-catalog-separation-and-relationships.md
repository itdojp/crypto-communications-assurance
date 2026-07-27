# ADR 0003: Security catalog separation, identity, and relationships

- Status: Proposed for CCA-120 review
- Date: 2026-07-28
- Decision owners: accountable human maintainers

## Context

CCA-110 supplies exact-byte packaging, source, producer, resolver, and compatibility identity. CCA-120 needs protocol-neutral security terminology that later profiles can select without turning catalog content into product claims, controls, results, or approvals. Combining security outcomes, attacker operations, attacker models, and threats would obscure their distinct meanings and create duplicate relationship authorities.

## Decision

### Three contracts only

Add three separate closed JSON Schema Draft 2020-12 contracts:

1. `cryptocomm-property-catalog/v1` describes bounded security, privacy, recovery, resilience, and evidence-publication outcomes.
2. `cryptocomm-attacker-catalog/v1` separates attacker capabilities from attacker models that compose those capabilities.
3. `cryptocomm-threat-catalog/v1` describes bounded adverse events or paths that reference capabilities and affected properties.

No catalog-set or registry contract is added. CCA-110 manifest and lock artifacts remain the authority for source identity, producer identity, exact bytes, and packaging. Catalogs do not repeat those identities.

### Stable entry identity

Entries use immutable semantic identifiers:

- `property.<domain>.<name>`;
- `capability.<domain>.<name>`;
- `attacker.<name>`;
- `threat.<domain>.<name>`.

Map keys must equal each entry's `id`. Domain-bearing identifiers must agree with the entry category or domain. A material meaning change requires a new identifier or new major contract/catalog version; editorial clarification must not silently redefine an identifier.

### Relationship authority

Only these v1 relationships are defined:

- property `dependsOn` references another property;
- attacker `capabilities` references capability entries;
- threat `capabilities` references capability entries;
- threat `affectedProperties` references property entries.

Property self-dependencies, property dependency cycles, dangling references, unknown relationship namespaces, and duplicate identifiers fail closed. Threat-to-attacker relationships are derived from shared capability references rather than duplicated in threat entries.

### Evidence lanes and decisions

Property `requiredEvidenceKinds` values name abstract evidence lanes only. They carry no execution status, evidence result, provenance, freshness, approval, risk acceptance, or release meaning. CCA-240 and later Issues retain those semantics.

Catalog entries do not define controls, risk scores, likelihood, severity, mitigation state, vulnerability confirmation, certification, or release decisions. A threat is not automatically a confirmed vulnerability, and an attacker model is not a universal requirement.

### Validation and safety

All catalog bytes enter through the existing CCA-110 strict exact-byte JSON decoder. Closed schema validation remains separate from deterministic semantic validation of identifier consistency, references, cycles, bounds, category coverage, and the data-only safety boundary.

Catalogs require `executable=false`, `networkRequired=false`, and `secretsAllowed=false`. Validation performs no network access, path resolution, execution, scanning, cryptographic operation, or external-tool call.

## Consequences

- Later profiles can select stable domain terms without gaining execution or decision authority.
- Separate contracts can evolve without conflating property, attacker, and threat meanings.
- Machine and human coverage matrices can review Issue-scope representation without becoming a fourth contract.
- CCA-110 exact-byte manifests can bind the three catalog instance bytes without a live lock or release identity.
- Catalog coverage is review evidence, not a security proof or completeness claim.

## Alternatives rejected

- **One combined catalog:** rejected because it conflates outcomes, capabilities, models, and adverse events.
- **A catalog-set or registry contract:** rejected because CCA-110 already supplies packaging and content identity.
- **Direct threat-to-attacker references:** rejected as a duplicate authority when capability composition already establishes applicability.
- **Risk scores or mitigation fields:** rejected because CCA-120 defines terminology and relationships, not risk or control decisions.
- **Protocol- or algorithm-specific entries:** rejected because the catalog must remain mechanism-neutral and does not implement cryptography.
