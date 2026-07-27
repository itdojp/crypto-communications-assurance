# Public and private evidence boundary

## Public repository material

The following material may be committed when it is intentionally public, reviewed,
licensed, and free of sensitive data:

- source code, schemas, and architecture documentation;
- public specifications and references with appropriate attribution;
- deterministic test cases using generated, fictional, or otherwise explicitly
  synthetic inputs;
- synthetic fixture digests and placeholder revisions that cannot be mistaken for
  observed production evidence;
- redacted process examples that disclose neither private findings nor target data.

Synthetic fixtures must be labeled in their directory documentation and in test
descriptions. They remain `synthetic` regardless of whether a validator accepts
them. Validation does not promote them to real evidence.

## Material that must remain outside Git

Do not commit, attach to a public Issue, or copy into a public PR:

- credentials, tokens, keys, secrets, or authentication material;
- customer identities, customer data, or contractual material;
- production or staging configurations and telemetry;
- raw audit evidence, private scanner output, exploit details, or restricted
  vulnerability reports;
- generated evidence that has not been intentionally approved as a synthetic
  fixture;
- personally identifiable or regulated information.

`.gitignore` reduces accidental inclusion of local environment files but is not a
security boundary. Contributors must review staged changes and use GitHub private
vulnerability reporting for sensitive security reports.

## Public catalog material

The CCA-120 authoritative catalogs contain protocol-neutral public definitions, assumptions, exclusions, relationships, and explanatory primary-source section identifiers. They contain no target-specific finding, customer data, private evidence, live source identity, credential, or approval field. The coverage matrix is a public review surface and not evidence that any product satisfies a property.

CCA-120 catalog fixtures remain explicitly `synthetic-test-only`. The synthetic CCA-110 manifest content-binds public catalog bytes under fictional source and producer identities; it is not a release manifest or live repository claim.

## Referencing private evidence

CCA-110 compatibility records may reference only content-bound synthetic or intentionally public evidence without embedding evidence bytes. Evidence map keys are bounded bundle-relative identifiers only. They are not repository authorities, network locators, private evidence paths, local absolute paths, or provenance records. The evidence value content-binds bytes but does not supply a location or access authority.

Evidence provenance, private evidence reference design, access control, correlation risk, retention, and freshness remain deferred to a separately reviewed contract, including CCA-240. CCA-110 does not define or implement private evidence handling.

## External services

Repository tests do not upload evidence or call an external LLM, scanner, or live
target. A future external integration requires an explicit Issue, data-flow and
retention review, least-privilege credentials, network policy, and human approval.

## Incident response

If sensitive material is discovered in repository history, stop further sharing,
notify the accountable maintainer privately, rotate affected credentials, and
follow the host's sensitive-data removal procedure. Do not repeat the secret in a
public remediation Issue or commit message.
