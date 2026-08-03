# ADR 0006: CCA-owned render plan and pinned ae-native projection

- Status: Accepted for CCA-210 v1
- Date: 2026-08-03
- Exact CCA implementation base: `c7d941d6aa1c6665122816736a86502490799c3a`
- Exact ae-framework target: commit `c5da6115638fdbfeebbc458b39fa6916db66afb0`, tree `0d69865b37a4476a20f0f1f1f42031967d3ec3a7`

## Context

CCA-120 catalogs and a CCA-130 resolved profile are protocol-neutral scope and
traceability authorities. The selected ae-framework schemas require
target-specific claims, assurance levels, lanes, evidence kinds, STRIDE/CWE
classifications, Context Pack paths, trust boundaries, and audit scope. Those
values are not safely derivable from catalog titles, definitions, categories,
module selections, attacker capabilities, or resolution states.

The native schemas also omit identities retained by CCA. In particular,
`security-audit-scope/v1` carries a commit but no Git tree, and
`assurance-profile/v1` carries Context Pack paths but no exact-byte digest.
Native shapes cannot carry the full CCA-240 subject/input/producer/tool/scope,
classification, freshness, and binding model.

## Decision

CCA owns one closed Draft 2020-12 semantic authority:
`cryptocomm-ae-render-plan/v1`. A separate pure renderer accepts only a token
returned by successful exact-byte/schema/semantic validation and may emit only:

1. `assurance-profile/v1`;
2. `security-claim/v1`;
3. `security-threat-model/v1`;
4. `security-audit-scope/v1`.

There is no CCA-210 render-result or output-index contract. Execution,
provenance, freshness, and exact record composition reuse
`cryptocomm-execution-result/v1`, `cryptocomm-evidence-provenance/v1`,
`cryptocomm-freshness-assessment/v1`, and
`cryptocomm-evidence-binding-set/v1` from CCA-240.

The plan exact-byte binds the five CCA inputs, selected existing Context Pack
files, target full commit and tree, all five pinned upstream schemas, and the
renderer source. It explicitly dispositions every selected property, threat,
evidence requirement, output, and scope as `render`, `unsupported`, or
`excluded-by-operator`. Unsupported/excluded values retain bounded reasons.

The exact CCA property ID is the generated claim ID in both native claim
surfaces. The exact CCA threat ID is the generated native threat ID. Claim
statements and types, claim kinds, criticality, A0–A4 levels, lanes, evidence
kinds, STRIDE/CWE values, related claims, scope, exclusions, and trust-boundary
facts are explicit plan values. The renderer does not infer them.

For the current threat-model projection, the native `frameworks` collection
contains `STRIDE` only. Explicitly selected CWE identifiers remain on their
individual threats unchanged. The pinned schema validates CWE lexical shape but
does not bind a dated general-CWE or CWE Top 25 membership set, so the renderer
adds one informational projection-loss diagnostic rather than asserting
`CWE_TOP_25`. A future Top 25 output requires an exact dated edition, exact
membership data, membership validation for every emitted CWE, and a separate
accountable-human decision.

Existing Context Packs are reference-only. Their original bytes are supplied
and bound outside the native path-only field; CCA-210 does not create their
objects, morphisms, diagrams, tests, conventions, or forbidden changes. A
requested assurance profile without a reviewed Context Pack reference fails
closed.

The CCA evidence-requirement vocabulary and the pinned native lane/kind enums
are non-equivalent. Each mapping is explicit. `operational-procedure` and
`human-review` remain unsupported unless the plan records a deliberately
narrower lossy projection; `waiver` never means human review. No mapping records
evidence existence, success, freshness, sufficiency, or satisfaction.

The full target tree remains in the plan and CCA-240 subject/provenance. The
native audit scope emits only the full commit because the pinned schema has no
tree field. The required `treeProjection` record makes this deliberate loss
literal.

The renderer emits UTF-8 JSON with two-space indentation, LF, one final newline,
fixed object-field order, and code-point-sorted set-like arrays and mappings. It
does not read the current time, filesystem, network, branch/tag, environment, or
target instructions. Optional native `generatedAt` and summary fields are
omitted.

The closed plan schema fixes `cca-ae-renderer/v1`, package version `0.0.0`, the
source path, and the SHA-256 of the exact current renderer source snapshot. Those
values are one reviewed identity tuple, not a moving alias. Once this v1 meaning
is accepted, a source change cannot silently rewrite only the fixed digest while
reusing the historical identity; it requires a reviewed implementation-ID,
package-version, or contract-version decision.

## Exact upstream pin and licensing

Only five reviewed Apache-2.0 schema byte sequences are copied under
`integrations/ae-framework/pins/c5da6115.../`. `UPSTREAM.json` records the
repository, commit, tree, selected path, Git blob SHA, exact-byte SHA-256, byte
length, purpose, license, and NOTICE handling. The repository `NOTICE`
reproduces the upstream attribution. Offline tests neither fetch nor execute
ae-framework.

## Rejected alternatives

- Direct resolved-profile-to-native generation: hides human decisions and loss.
- Automatic property-title/description claims: changes catalog meaning into an
  unreviewed target assertion.
- Automatic evidence, STRIDE/CWE, scope, trust, severity, or assurance-level
  crosswalks: creates semantic authority not present in CCA inputs.
- A CCA-210 output-index/render-result contract: duplicates CCA-240 composition.
- Full Context Pack or claim-evidence-manifest generation: crosses the reference
  and result/satisfaction boundaries.
- Following upstream `main`: violates the accountable-human exact pin.

## Consequences and retained limits

- `property != product claim`.
- `generated native claim != satisfied claim`.
- `shape-valid != semantically compatible`.
- `pass render != evidence satisfied`.
- `Context Pack reference != Context Pack synthesis`.
- `full commit in native audit scope != full CCA target identity`.
- `explicit STRIDE/CWE mapping != automated threat classification`.
- `renderer != ae-framework execution`.
- `pinned schema conformance != product-wide compatibility`.

Human mapping errors and undocumented upstream consumer semantics remain
residual risks. CCA-330 owns later bounded compatibility testing and any
permitted compatibility wording. This decision conveys no evidence sufficiency,
claim satisfaction, product security, approval, risk acceptance, certification,
production readiness, release readiness, or publication authority.
