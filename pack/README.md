# Pack data

`pack/catalogs/v1/` contains the proposed CCA-120 authoritative public, JSON-first property, attacker/capability, and threat catalog instances.

- `property-catalog.json`: 40 protocol-neutral outcomes;
- `attacker-catalog.json`: 28 capabilities and 8 bounded attacker models;
- `threat-catalog.json`: 36 bounded adverse events or paths;
- `coverage-matrix.json`: machine-readable Issue-scope review evidence, not a contract, catalog-set, registry, product claim, or security proof.

CCA-110 manifest and lock contracts remain the source, producer, packaging, and exact-byte identity authority. Catalogs do not self-identify a repository revision or producer. The committed synthetic manifest fixture content-binds the three exact catalog byte sequences without creating a live release manifest or lock.

The catalog data implements no cryptographic primitive or protocol, selects no algorithm or deployment, performs no network activity, and conveys no evidence result, human approval, vulnerability confirmation, certification, release authority, or completeness claim.

`pack/modules/v1/capability-module-catalog.json` is the CCA-130 authoritative public module catalog. It contains 14 available protocol-neutral modules and one explicit unsupported boundary module. Together they cover confidentiality/integrity, authentication, identity/session/transcript binding, replay/ordering, nonce/randomness, key derivation/separation, key lifecycle, downgrade/agility, forward-secrecy assumptions, post-compromise-recovery assumptions, metadata privacy, fail-closed/state recovery, evidence-publication boundaries, and a bounded active-network attacker scope.

The module catalog content-binds the exact three CCA-120 catalog byte sequences. It contains no source or producer identity because CCA-110 remains that authority. It defines no default, recommended, strongest, certified, universal, product-specific, or deployment profile. An available module is an assurance-scope selection, not an attacker capability or product capability; the unsupported private-provenance entry records the CCA-240 boundary rather than adding evidence semantics.
