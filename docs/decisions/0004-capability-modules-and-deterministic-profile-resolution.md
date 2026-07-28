# ADR 0004: Capability modules and deterministic profile resolution

- Status: Proposed for CCA-130 review
- Date: 2026-07-29
- Decision owners: accountable human maintainers

## Context

CCA-110 supplies exact-byte packaging and identity contracts. CCA-120 supplies separate property, attacker/capability, and threat catalogs without source or producer identity. CCA-130 needs reusable assurance-scope composition without turning a selection into a product feature, control, policy decision, execution request, evidence result, product claim, or approval.

## Decision

### Separate module, request, and resolved-profile contracts

Add three separate closed JSON Schema Draft 2020-12 contracts:

1. `cryptocomm-capability-module-catalog/v1` defines reusable available and unsupported assurance-scope modules.
2. `cryptocomm-profile-request/v1` records one explicit operator selection of one or more module identifiers.
3. `cryptocomm-resolved-profile/v1` records the deterministic expansion of that request.

No registry, policy, approval, execution, evidence, release, or certification contract is added. Stable IDs use `module.<domain>.<name>` and `profile.<domain>.<name>`. Module map keys equal embedded module IDs. A material semantic change requires a new identifier or a new major contract/catalog version.

The following distinctions are normative boundaries:

- `module != attacker capability`
- `module != product capability`
- `profile request != approval`
- `resolved profile != product claim`
- `resolution outcome != evidence status`
- `complete resolution != product security`

### Exact input binding

The module catalog binds each CCA-120 property, attacker, and threat catalog by contract ID, catalog ID, catalog version, and SHA-256 of the exact original bytes. The request binds the exact module-catalog bytes using the same four-part model. The resolved profile repeats the exact module-catalog and three CCA-120 bindings actually used.

Strict decoding validates but never rewrites input. JSON whitespace, member order, encoding, and line endings remain part of exact input identity. CCA-110 stays the source, producer, and packaging identity authority; CCA-130 does not duplicate those fields.

### Module forms and dependency closure

An available module carries at least one direct property, capability, attacker, or threat selection; no class exceeds 32 direct selections. It may require up to eight module IDs and carries explicit assumptions and exclusions. An unsupported module carries a bounded reason and scope plus explicit assumptions and exclusions, and has neither catalog selections nor dependencies.

Module dependencies are directed and transitive. Validation rejects malformed identity, key/ID mismatch, duplicate or dangling selections, self/duplicate/dangling dependencies, dependency cycles, invalid unsupported forms, and unsafe data-boundary flags. A selected available module expands its complete dependency closure. A selected unsupported module remains visible as `unsupported`; an available module depending on a non-resolved module becomes `unresolvable`.

### Conflict authority

The module catalog is the sole conflict authority. Each conflict is stored once as a canonical unordered pair whose two IDs are in ascending code-unit order. Validation rejects self-conflicts, duplicate or reversed duplicate pairs, non-canonical order, dangling IDs, and a module whose own dependency closure contains both conflict sides.

Resolution applies no precedence and selects no winner. When the selected closure contains a conflict, both conflict sides become `unresolvable`; that outcome propagates to every available module depending on either side. Both sides remain visible. A known unsupported module remains `unsupported` when selected without an active conflict.

### Literal outcomes and overall state

Every directly requested or transitively required module has one literal outcome:

- `resolved`: a known available module whose dependencies resolve and whose selected closure has no conflict that blocks it;
- `unknown`: a syntactically valid requested ID absent from the module catalog;
- `unsupported`: a known module in the unsupported form;
- `unresolvable`: a known available module blocked by conflict or a non-resolved dependency.

The overall profile is `complete` only when every visible module is `resolved`; otherwise it is `incomplete`. These words describe repository-local profile resolution only. They are not `pass`, `fail`, `skip`, `unsupported`, `timeout`, `tool-error`, or `not-run` execution/evidence results, and convey no approval or security conclusion.

### Catalog closure and traceability

Only resolved modules contribute catalog selections. Resolution includes:

- direct properties and every transitive property dependency;
- direct capabilities;
- direct attacker models and the capabilities they reference;
- direct threats, the capabilities they reference, and the properties they affect;
- transitive dependencies of every property added through any route.

Threats do not infer attacker models. Each resolved selection records every source module together with its inclusion reason. Module assumptions and exclusions remain visible with their source module IDs, including known unsupported or unresolvable modules. Resolution does not infer that an assumption is true and does not reinterpret an exclusion as a waiver, control, risk acceptance, approval, or evidence result.

### Deterministic serialization

The resolver is a pure repository-local function over exact input bytes. Invalid strict JSON, schema-invalid contracts, invalid catalog/module semantics, or any binding mismatch returns bounded, stable, machine-readable diagnostics and no resolved profile. A contract-valid request containing unknown, unsupported, or unresolvable modules still produces an incomplete resolved profile.

Output uses UTF-8, two-space indentation, LF, one final newline, fixed field order, lexicographically sorted map keys, and sorted set-like arrays. Request module order cannot affect bytes. Output excludes timestamps, run IDs, hostnames, local paths, credentials, mutable branch names, request-byte digests, and generated human approval.

### CCA-240 boundary

CCA-130 defines no execution status, evidence result/class, provenance, freshness, retention, access control, risk acceptance, approval, certification, or release authorization. Those semantics remain reserved for CCA-240 and later separately authorized work. The resolver performs no external call, live probe, private-evidence access, cryptographic protocol operation, or cryptographic primitive implementation.

## Consequences

- CCA-120 terms can be composed and traced without duplicating their meanings or identity authority.
- Exact-byte bindings make input mutation explicit and fail closed.
- Conflict and dependency failures remain visible rather than being silently discarded.
- Byte-stable output can be golden-tested and content-bound by CCA-110 manifests.
- Complete resolution establishes only deterministic composition, not product satisfaction, evidence, approval, certification, vulnerability absence, production readiness, or product security.

## Alternatives rejected

- **One combined module/profile artifact:** rejected because reusable definitions, operator intent, and deterministic expansion have different authorities.
- **A module registry or policy engine:** rejected because it would add governance and approval authority outside CCA-130.
- **Implicit conflict precedence:** rejected because only an accountable human can approve future precedence semantics.
- **Input canonicalization:** rejected because CCA-110/120 exact-byte identity must remain transparent.
- **Threat-to-attacker inference:** rejected because attacker selection is explicit and CCA-120 defines capability composition as the only shared relationship.
- **CCA-240 status or provenance fields:** rejected because execution/evidence semantics require separate contract and privacy review.
