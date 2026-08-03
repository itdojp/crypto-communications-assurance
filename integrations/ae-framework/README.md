# ae-framework integration

CCA-210 uses a CCA-owned `cryptocomm-ae-render-plan/v1` as the semantic
authority and projects only explicitly reviewed values into four native input
shapes:

- `assurance-profile/v1`;
- `security-claim/v1`;
- `security-threat-model/v1`;
- `security-audit-scope/v1`.

The exact offline validation target is `itdojp/ae-framework` commit
`c5da6115638fdbfeebbc458b39fa6916db66afb0`, tree
`0d69865b37a4476a20f0f1f1f42031967d3ec3a7`. Only the five schemas required for
those outputs and supplied Context Pack validation are copied under `pins/`.
`UPSTREAM.json` records their upstream path, Git blob SHA, exact-byte SHA-256,
byte length, purpose, Apache-2.0 license, and NOTICE handling.

Repository tests are offline and do not execute ae-framework. Schema
conformance applies only to generated fixture shapes against these exact bytes;
it is not product-wide compatibility, semantic equivalence, evidence
sufficiency, claim satisfaction, approval, certification, or release authority.
CCA-210 does not synthesize Context Packs or generate claim-evidence manifests,
policy decisions, reviews, findings, summaries, code maps, execution plans, or
publication artifacts.
