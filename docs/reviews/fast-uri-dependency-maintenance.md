# fast-uri dependency maintenance

This isolated maintenance change addresses the known fast-uri advisories tracked
in Issue #30. The root pnpm override selects exact **3.1.6** for the transitive
dependency used by `ajv@8.20.0`. The prior 3.1.5 proposal is insufficient for the
additional advisories; AJV's version and all unrelated dependencies are retained.

## Advisory scope

The upstream advisories describe URI-parser differences that can affect consumers
using parsed/normalized URIs to make network or host-policy decisions:

- [Backslash authority confusion (GHSA-7p8r-x3mc-p8w7)](https://github.com/fastify/fast-uri/security/advisories/GHSA-7p8r-x3mc-p8w7), fixed in v3.1.5.
- [Encoded scheme normalization (GHSA-jqff-g426-hqxp)](https://github.com/fastify/fast-uri/security/advisories/GHSA-jqff-g426-hqxp), fixed in v3.1.6.
- [Malformed IPv6 normalization (GHSA-f65p-4m7j-42xc)](https://github.com/fastify/fast-uri/security/advisories/GHSA-f65p-4m7j-42xc), fixed in v3.1.6.
- [Repeated hostname decoding (GHSA-fph4-wmhf-6fwf)](https://github.com/fastify/fast-uri/security/advisories/GHSA-fph4-wmhf-6fwf), fixed in v3.1.6.
- [Scheme-relative IDN canonicalization (GHSA-5jgf-p345-68v8)](https://github.com/fastify/fast-uri/security/advisories/GHSA-5jgf-p345-68v8), fixed in v3.1.6.

CCA's repository-local schema validation is not an outbound URL allowlist or
network client. Updating the vulnerable dependency does not establish a deployed
exploit, universal URI safety, or vulnerability absence.

## Regression and maintenance boundary

`tests/fast-uri-security.test.ts` resolves fast-uri through the contracts
package's actual installed AJV, checks policy/lock/runtime version agreement,
and exercises synthetic URI data plus ordinary local Draft 2020-12 references.
It runs through the existing `test` and `verify` scripts without new runtime
dependencies, network requests, DNS, or upstream execution. The cases are bounded
regressions, not a replacement for upstream tests or a complete URI-policy suite.
In particular, `normalize` can preserve malformed input; it must not be treated
as a validator or approval decision.

Future dependency changes must update the exact override, lockfile and regression
expectations together after reviewing the then-current advisories. The explicit
override can be removed only after a reviewed replacement prevents reintroduction
of affected versions. No direct dependency, renderer identity, schema, fixture,
or upstream pin is changed here. Vitest maintenance remains in separate PR #29.

This branch must remain unmerged pending accountable-human review. Merging any
maintenance PR advances main and requires reevaluation of PR #24's exact-base
authorization and of other dependency PRs' integration state. Tests and automated
reviews do not grant merge, risk acceptance, satisfaction, or release authority.
