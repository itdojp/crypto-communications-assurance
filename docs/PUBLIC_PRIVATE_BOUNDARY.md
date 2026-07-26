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

## Referencing private evidence

CCA-110 compatibility records may reference only content-bound synthetic or intentionally public evidence without embedding evidence bytes. A public reference must not contain a private location, access token, local absolute path, hostname-local identity, sensitive digest that enables correlation, or raw private evidence.

Private evidence reference design remains deferred to a separately reviewed contract with an explicit data-flow, access-control, and correlation-risk decision. CCA-110 does not define or implement private evidence handling.

## External services

Repository tests do not upload evidence or call an external LLM, scanner, or live
target. A future external integration requires an explicit Issue, data-flow and
retention review, least-privilege credentials, network policy, and human approval.

## Incident response

If sensitive material is discovered in repository history, stop further sharing,
notify the accountable maintainer privately, rotate affected credentials, and
follow the host's sensitive-data removal procedure. Do not repeat the secret in a
public remediation Issue or commit message.
