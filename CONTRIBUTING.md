# Contributing

## Change workflow

1. Open or reuse one GitHub Issue that defines the goal, scope, non-goals, safety
   constraints, and acceptance criteria.
2. Create one dedicated branch and worktree from the current `main`.
3. Make the smallest change that satisfies the Issue. Do not expand a bootstrap
   task into a cryptographic implementation, product certification, or live
   assurance exercise.
4. Open a Draft PR early and link the Issue.
5. Run the required validation at the exact proposed head revision.
6. Resolve actionable review findings or hand them off explicitly.
7. Leave merge, Issue closure, release, publication, and risk acceptance to the
   accountable human maintainer.

Direct source changes to `main` are not part of the normal workflow.

## Local prerequisites

- Node.js `>=22 <23`;
- Corepack;
- the exact pnpm version declared in the root `package.json`.

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm run verify
git diff --check
```

Installing dependencies may access the configured package registry. Repository
tests and verification must not require an external model, scanner, registry
fallback, or live target.

## Evidence and status reporting

Record the command, exact source revision, environment, and literal outcome.
Only an executed check that meets its stated success criteria is `pass`. Use the
distinct vocabulary in [`docs/STATUS_SEMANTICS.md`](docs/STATUS_SEMANTICS.md) for
`fail`, `skip`, `unsupported`, `timeout`, `tool-error`, and `not-run`.

Synthetic fixtures are test inputs only. They cannot support a claim about a real
product, vulnerability, certification, approval, or release.

## Contract changes

- JSON is authoritative; Markdown is explanatory or a review surface.
- Keep schemas closed unless an Issue approves an extension point.
- Add positive and negative fixtures for schema changes.
- Bound repository-relative paths and content-bind referenced artifacts with
  SHA-256 digests.
- Preserve `executable=false`, `networkRequired=false`, and
  `secretsAllowed=false` unless a later, separately reviewed contract replaces
  this bootstrap contract. Do not relax these values in place.

## Security reports

Do not open a public Issue containing a suspected vulnerability, exploit detail,
secret, customer data, or private evidence. Follow [`SECURITY.md`](SECURITY.md).
