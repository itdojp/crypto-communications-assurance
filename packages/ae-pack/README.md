# ae-framework native fixture material

CCA-210 keeps the semantic render plan and pure implementation in the private
repository-local contracts package. Representative generated native bytes live
under `fixtures/valid/cca-210/rendered/`; no package is published from this
directory.

Only four exact-pin input shapes are supported: `assurance-profile/v1`,
`security-claim/v1`, `security-threat-model/v1`, and
`security-audit-scope/v1`. Context Packs are existing operator-selected
references, not generated content. The committed shapes are
`synthetic-test-only`; validation against the pinned schemas is not a
compatibility, satisfaction, approval, certification, production, or release
claim.
