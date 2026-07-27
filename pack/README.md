# Pack data

`pack/catalogs/v1/` contains the proposed CCA-120 authoritative public, JSON-first property, attacker/capability, and threat catalog instances.

- `property-catalog.json`: 40 protocol-neutral outcomes;
- `attacker-catalog.json`: 28 capabilities and 8 bounded attacker models;
- `threat-catalog.json`: 36 bounded adverse events or paths;
- `coverage-matrix.json`: machine-readable Issue-scope review evidence, not a contract, catalog-set, registry, product claim, or security proof.

CCA-110 manifest and lock contracts remain the source, producer, packaging, and exact-byte identity authority. Catalogs do not self-identify a repository revision or producer. The committed synthetic manifest fixture content-binds the three exact catalog byte sequences without creating a live release manifest or lock.

The catalog data implements no cryptographic primitive or protocol, selects no algorithm or deployment, performs no network activity, and conveys no evidence result, human approval, vulnerability confirmation, certification, release authority, or completeness claim.
