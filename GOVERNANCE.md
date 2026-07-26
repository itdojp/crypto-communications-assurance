# Governance

## Accountable decisions

Human maintainers are accountable for scope acceptance, merge, risk acceptance,
release, publication, disclosure, and compatibility commitments. Automated agents,
tests, scanners, and formal tools may produce evidence but cannot make those
decisions.

The repository currently uses a solo-maintainer profile. The required GitHub human
approval count is therefore zero; that numeric setting must not be represented as
an automated approval or as evidence that review occurred. Exact-head CI, resolved
review conversations, complete evidence, and a recorded human merge decision are
the compensating controls.

High-impact decisions involving a cryptographic primitive or protocol may require
external expert review as separately recorded release evidence. This repository
does not implement those primitives or protocols.

## Change control

- Each change starts from an Issue with explicit scope and non-goals.
- Source changes use a dedicated branch and Draft PR.
- Checks report the exact proposed head, not a different or stale revision.
- Required checks are added to branch policy only after their exact names have
  succeeded on `main` or the exact-head PR.
- Squash merging is the normal merge method; merge and release remain human
  actions.

## Emergency decision path

An emergency does not silently weaken repository policy. If an accountable human
maintainer must use an administrative bypass, the maintainer records on the PR:

1. the emergency condition and impact;
2. the exact rule or check bypassed;
3. the available evidence and unresolved risk;
4. the human decision and timestamp;
5. the remediation Issue and target date.

An agent may prepare this record but cannot exercise the bypass or make the human
decision. There is no undocumented agent, application, or administrator bypass.

## Release governance

No release process exists during bootstrap. Tag protection, signed annotated tags,
checksums, SBOMs, attestations, and artifact-to-commit binding must be designed and
tested with a later reviewed release workflow. Until then, no release or package is
published and no release/tag ruleset is implied by documentation alone.
