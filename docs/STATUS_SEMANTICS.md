# Status semantics

## Closed status vocabulary

The following terms describe the literal outcome of one identified check at one
source revision. They do not imply human approval, product certification, release
readiness, or absence of vulnerabilities.

| Status | Meaning |
| --- | --- |
| `pass` | The check executed and met its stated success criteria for the identified inputs and revision. |
| `fail` | The check executed and did not meet at least one stated success criterion. |
| `skip` | The check was intentionally not executed because an explicit, documented conditional rule applied. |
| `unsupported` | The check cannot run for the identified platform, input, feature, or plan under its declared support contract. |
| `timeout` | Execution began but exceeded its declared time bound before a result was established. |
| `tool-error` | Execution could not establish the intended result because the tool, runner, dependency, or harness malfunctioned. |
| `not-run` | No execution was attempted and no more specific status applies. |

## Non-promotion rules

- Only an executed check that meets its criteria is `pass`.
- `skip`, `unsupported`, `timeout`, `tool-error`, and `not-run` are not synonyms for
  each other and are never converted to `pass`.
- A successful schema validation establishes conformance to that schema only. It
  does not establish truth, completeness, security, compatibility, or approval.
- A scanner, model, test, or formal tool is an evidence producer, not a human
  approver.
- Synthetic and test-only evidence stays synthetic or test-only after a `pass`.
- An absence of findings is not proof of absence of vulnerabilities.

## Catalog evidence needs are not results

CCA-120 property `requiredEvidenceKinds` values identify abstract evidence lanes such as `specification`, `behavioral-test`, `formal-model`, or `human-review`. They contain no status from this document. Naming an evidence need does not mean work executed, evidence exists, a result passed, or a human approved it. CCA-240 records results and provenance without deciding that these evidence needs are satisfied.

## Profile resolution outcomes are not results

CCA-130 module outcomes `resolved`, `unknown`, `unsupported`, and `unresolvable` describe deterministic composition. Overall `complete` and `incomplete` describe whether every visible module resolved. None is a check status from the table above. In particular, module `unsupported` is not the execution status `unsupported`; the artifact and vocabulary context must remain explicit.

Resolution performs no assurance check and emits no evidence result. `resolved` does not mean `pass`; `unresolvable` does not mean `fail` or `tool-error`; `complete` does not mean product satisfaction, product security, approval, certification, production readiness, or release readiness. CCA-240 retains execution/evidence status, provenance, and freshness semantics.

## CCA-240 status-dependent record

A durable `cryptocomm-execution-result/v1` record contains:

- check identifier and tool version;
- exact source revision and input identity;
- start and completion time or declared timeout;
- one status from the vocabulary above;
- concise reason, including the skip or unsupported condition when applicable;
- content-bound output reference where an approved evidence system exists;
- bounded diagnostics and advisory-only retry information.

`pass` and `fail` are completed forms and may reference all four artifact roles.
`timeout` and execution/post-processing `tool-error` may reference `partial`,
`diagnostic`, or `log`; preflight `tool-error`, `skip`, `unsupported`, and
`not-run` may reference `diagnostic` or `log` only. A non-completed execution
cannot bind `substantive-result`.

The machine-readable matrix is
[`pack/evidence/v1/execution-status-matrix.json`](../pack/evidence/v1/execution-status-matrix.json).
No result status is claim satisfaction, evidence sufficiency, accountable-human
approval, certification, risk acceptance, or release authority. A retry creates a
new record and never rewrites the original literal state.

## CCA-210 renderer application

CCA-210 uses `pass` for a representative renderer execution only when the
declared deterministic byte transformation and exact pinned-schema validation
completed. It does not mean a native claim is satisfied, required evidence
exists or is sufficient/fresh, the target is secure, or ae-framework accepted or
executed the artifact. Unsupported/excluded render-plan mappings remain their
literal dispositions and never become pass.
