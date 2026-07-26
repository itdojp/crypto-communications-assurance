# Agent operating instructions

These instructions apply to automated coding, review, and analysis agents working
in this repository.

## Authority and scope

- Treat the active GitHub Issue as the upper bound of work.
- Use a dedicated branch and Draft PR for source changes. Do not push source
  changes directly to `main`.
- Do not merge, close an Issue, release, publish, accept risk, or approve a change
  on behalf of a human maintainer.
- AI, scanner, test, and formal-tool results are evidence only. They are not human
  approval.

## Safety invariants

- Do not implement cryptographic primitives, cryptographic protocols, or custom
  cryptographic algorithms.
- Do not probe production, staging, or any external host.
- Do not call an external LLM, scanner, registry fallback, or live service from a
  repository test.
- Do not modify the `ae-framework` or `genai-repo-auditor` repositories as part of
  work here.
- Do not commit secrets, customer data, production evidence, or raw private audit
  evidence. Synthetic fixtures must be labeled and must remain synthetic.
- Preserve the distinct statuses defined in `docs/STATUS_SEMANTICS.md`. Never turn
  an unexecuted check into `pass`.

## Engineering baseline

- Use Node.js `>=22 <23` and the exact pnpm version in `packageManager`.
- Keep runtime contracts JSON-first and validate them with JSON Schema Draft
  2020-12.
- Pin direct dependencies exactly and commit `pnpm-lock.yaml`.
- Keep tests deterministic and repository-local after dependency installation.
- Run `pnpm install --frozen-lockfile`, `pnpm run verify`, and `git diff --check`
  before handing a change to a human maintainer.
- Record literal results, exact commit revisions, limitations, and unavailable
  checks in the Draft PR.
