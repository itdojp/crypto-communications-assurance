# Synthetic fixtures

Every artifact under this directory is synthetic and test-only. It is not derived
from a customer, production system, staging system, live scan, or private audit.

- `valid/` contains candidates expected to conform to the bootstrap schema.
- `invalid/` contains deliberately nonconforming candidates used to prove
  rejection behavior.
- `artifacts/` contains non-sensitive synthetic bytes referenced by a fixture.

A fixture that passes validation remains synthetic. It cannot support a real-world
security, vulnerability, compatibility, approval, certification, or release claim.
