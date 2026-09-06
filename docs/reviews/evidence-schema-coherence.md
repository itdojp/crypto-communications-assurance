# Shared CCA-240 schema regression boundary

Issue: #25 (CCA-QA-001). Review baseline:
`c7d941d6aa1c6665122816736a86502490799c3a`.

The four evidence schemas intentionally remain self-contained. Thirty-six
identity, subject, input, producer, tool, environment, scope, safety, and
diagnostic definitions are duplicated. `tests/evidence-schema-coherence.test.ts`
turns their previously manual coherence check into an offline regression.

## Run

```bash
pnpm exec vitest run tests/evidence-schema-coherence.test.ts
pnpm run test
pnpm run verify
```

The existing full-test/verify commands discover the test automatically. The
explicit focused `check:schemas` file list is unchanged; it does not independently
run this additional regression.

## What is checked

The checked-in inventory in `tests/helpers/evidence-schema-coherence.ts` names
all 36 common definitions. Every inventory entry must be present in every
strict-decoded schema, including the comparison baseline. The complete definition
structures must agree. Object member insertion order is immaterial; arrays and
all values remain significant. Contract-specific definitions are not forced to
be equal. The lexically first available schema is a comparison baseline, not a
claim that it is the correct definition.

Mutation tests change only in-memory synthetic copies. They cover a changed
copy, missing definitions in the baseline or all schemas, malformed definition
maps, nested safety flags, binding/digest/timestamp constraints, member order,
array changes, and contract-specific additions. Real schema and fixture bytes
are never rewritten by the test.

## Limits

Structural equality is deliberately stricter than semantic equivalence: even
array reordering requires review, including set-like schema arrays. Equality
cannot detect a consistently wrong change applied to all four schemas. The
existing schema/semantic/fixture tests and human contract-version review remain
necessary. This helper accepts trusted strict-decoded repository schema objects;
it is not a public runtime validator or a sandbox for hostile JavaScript objects.

No product contract, schema identity, runtime code, dependencies, package scripts,
workflow, upstream pin, or authority is changed. Keep this Draft PR separate from
concurrently owned PR #24; prefer merging after that PR's exact-base decision.
