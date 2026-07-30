# CCA-240 execution, provenance, freshness, and binding contracts

CCA-240 defines four closed JSON Schema Draft 2020-12 contracts. They preserve
four different authorities instead of producing an aggregate assurance decision:

1. `cryptocomm-execution-result/v1` records one literal terminal execution or
   non-execution result.
2. `cryptocomm-evidence-provenance/v1` records exact subject, input, producer,
   tool, environment, scope, classification, and artifact provenance.
3. `cryptocomm-freshness-assessment/v1` records a pure assessment from explicit
   caller-supplied comparison and validity facts.
4. `cryptocomm-evidence-binding-set/v1` binds exact bytes of one record of each
   preceding kind. It is a composition root, not a storage system or decision.

## Execution-status matrix

The machine-readable source is
[`pack/evidence/v1/execution-status-matrix.json`](../pack/evidence/v1/execution-status-matrix.json).
Retry data is advisory only and never changes the original status.

| Status | Attempt | Intended execution | Completed substantive result | Permitted artifact roles |
| --- | --- | --- | --- | --- |
| `pass` | yes | yes | criteria met | substantive-result, partial, diagnostic, log |
| `fail` | yes | yes | criteria not met | substantive-result, partial, diagnostic, log |
| `skip` | no | no | none | diagnostic, log |
| `unsupported` | no | no | none | diagnostic, log |
| `timeout` | yes | began | none | partial, diagnostic, log |
| `tool-error` preflight | yes | no | none | diagnostic, log |
| `tool-error` execution/post-processing | yes | yes | none | partial, diagnostic, log |
| `not-run` | no | no | none | diagnostic, log |

A non-completed execution cannot reference a `substantive-result`. `pass` means
only that the declared check completed and its declared criteria were met.
`fail` means only that the completed check did not meet those criteria. Neither
status evaluates a catalog evidence requirement, claim, approval, certification,
or release gate.

All timestamps are caller-supplied UTC values with one to nine optional
fractional-second digits. Their closed schema validates calendar day/month and
Gregorian leap-year combinations; a lexically shaped but impossible date is not
an instant and is rejected. A completed execution additionally requires
`completedAt` to be equal to or later than `startedAt`.

## Evidence classification matrix

The axes are independent. The machine-readable matrix is
[`pack/evidence/v1/evidence-classification-matrix.json`](../pack/evidence/v1/evidence-classification-matrix.json).

| `evidenceOrigin` | `useRestriction` | Allowed | Meaning |
| --- | --- | --- | --- |
| `synthetic` | `test-only` | yes | fabricated/substituted evidence restricted to tests |
| `synthetic` | `policy-evaluable` | **no** | structurally rejected promotion |
| `real` | `test-only` | yes | non-synthetic observation deliberately restricted to tests |
| `real` | `policy-evaluable` | yes | later policy evaluation is permitted, but no policy result is implied |

`real` records origin only. `policy-evaluable` records permitted later use only.
No validator silently promotes `synthetic` to `real` or `test-only` to
`policy-evaluable`.

Committed examples use `fixtureClassification: synthetic-test-only`, which
requires `evidenceOrigin: synthetic` and `useRestriction: test-only`. Tests cover
the unmarked `real` and `policy-evaluable` lexical forms with in-memory candidates
only, so no committed fixture can be admitted to later policy evaluation.

## Subject and provenance identity

The subject is an explicit discriminated union:

- `cca-110-manifest`: exact contract ID, manifest/pack record ID, byte length,
  and SHA-256 of exact manifest bytes;
- `git-revision`: provider-scoped repository identity plus full 40-hex Git SHA-1
  commit and tree object IDs, matching the existing CCA-110 Git identity form;
- `contract-artifact`: contract ID, record ID, byte length, and SHA-256 of exact
  artifact bytes.

The implementation performs no fallback or inference between forms. Branches,
tags, abbreviated revisions, URLs, hostnames, and local paths are not subject
identity.

Every input binds its stable ID, original-byte SHA-256, byte length, media type,
and applicable contract identity. Empty input bytes are valid and remain an
explicit zero-length SHA-256 binding, including in selected freshness
fingerprints. External bytes are never re-serialized before hashing. Producer
identity is either an immutable software implementation or an
opaque human operator ID. Human-produced evidence remains evidence, not approval.
A tool is either identified by stable tool/version/implementation identity or
explicitly `not-applicable`. Environment identity is explicitly `recorded` or
`not-recorded`. Operator scope is explicit and bounded.

## Public-content and private-opaque artifacts

`public-content` references bind public-approved content with exact SHA-256,
byte length, media type, logical artifact ID, and role. `private-opaque`
references contain only a bounded operator-controlled opaque ID, the literal
`private` classification, logical artifact ID, and role.

A `private-opaque` artifact reference inside a public-safe provenance record has
no plaintext digest, byte length, media type, storage location, customer identity,
local path, or private storage metadata. It binds the opaque reference rather than
private bytes and does not prove that a sidecar exists. Private storage, sidecar
contracts, HMAC, encryption, credentials, access control, and key lifecycle are
deferred.

## Pure freshness decision order

The caller supplies intent/context, `asOf`, selected expected and observed exact
binding fingerprints, availability/verification facts, optional clock trust, and
explicit expiry/supersession/revocation/invalidation facts. Selected lifecycle
facts identify their authority. The repository-local assessor reads no current
clock, network, branch, tag, environment, or external revocation service.

The decision order is:

1. no request or no context -> `not-assessed`;
2. any selected exact identity/binding difference -> `mismatched`;
3. identities match and expiry/supersession/revocation/invalidation applies -> `stale`;
4. a required fact, verification, authority result, or required clock trust is unavailable -> `unknown`;
5. every selected requirement is known, matched, and valid -> `fresh`.

If time is not selected, clock trust is `not-required`. If time is selected,
`untrusted` or `unknown` clock trust cannot produce `fresh`. An active context
must select at least one requirement; this prevents a vacuous fresh result.

## Binding-set composition

The binding set repeats the exact subject and scope and binds the contract ID,
record ID, byte length, and original-byte SHA-256 of exactly one execution
result, provenance record, and freshness assessment. Freshness is never absent;
use an explicit `not-assessed` record. Semantic validation verifies the entire
chain, repeated subject/input/producer/tool/environment/scope identity, artifact
IDs/roles, fixture classification, and freshness state consistency. If any
committed fixture record carries `fixtureClassification: synthetic-test-only`,
that marker must be present on every record in the binding chain; provenance is
therefore constrained to `synthetic` plus `test-only` and cannot be replaced by
an unmarked `real` plus `policy-evaluable` record.

The binding set contains no aggregate status, winner, precedence, evidence
sufficiency, claim satisfaction, human approval, certification, risk acceptance,
or release status. It does not embed artifact bytes or storage locations.

## Non-promotion rules

The following statements are normative boundaries:

- `pass != evidence requirement satisfied`
- `real != fresh`
- `policy-evaluable != policy satisfied`
- `fresh != sufficient`
- `evidence result != human approval`
- `scanner finding != confirmed vulnerability`
- `no findings != satisfied claim`
- `local proof != machine-checked proof`
- `runtime mitigation != absence of a bug`
- `binding set != evidence storage`

Schema validity and exact-byte equality establish neither truth nor authenticity.
CCA-240 defines no ae-framework or GenAI Repo Auditor adapter, mapping authority,
or compatibility claim.

## Bounds and deterministic output

The strict decoder retains the 1,048,576-byte per-artifact and 128-container
limits. A record contains at most 64 exact inputs, 64 artifacts (and therefore at
most 64 private opaque references), and 256 diagnostics. Identifiers, versions,
reasons, scope, authorities, media types, and lists are bounded.

Repository-generated JSON is UTF-8 with two-space indentation, LF, one final
newline, lexicographically sorted object keys, and sorted set-like arrays.
Diagnostic arrays are sorted explicitly by `code`, then `path`, then `message`.
Timestamps are caller facts. Deterministic serialization applies only to generated
records; exact external input bytes are never canonicalized before hashing.
