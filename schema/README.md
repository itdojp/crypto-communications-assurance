# Schemas

JSON files in this directory are the authoritative machine contracts.

`cryptocomm-pack-v1.schema.json` is a closed Draft 2020-12 bootstrap envelope. It
requires a source revision, compatibility declarations, and a path-keyed artifact
map whose bounded repository-relative keys each bind to one SHA-256 digest. It also
requires false safety constants for execution, network, and secrets.

Schema conformance alone establishes none of truth, completeness, compatibility,
security, certification, human approval, or release readiness.
