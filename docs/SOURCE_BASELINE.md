# CCA-120 terminology source baseline

CCA-120 paraphrases public primary sources to establish a reviewable terminology baseline. A reference explains terminology only. It is not adoption of a protocol, proof of compatibility, a standards-compliance claim, certification, or evidence that a product satisfies a property.

| Source identifier | Public primary source | Sections used | Bounded use |
| --- | --- | --- | --- |
| `rfc3552` | [RFC 3552](https://www.rfc-editor.org/rfc/rfc3552.html), BCP 72 (July 2003) | 2, 2.1–2.3, 3, 3.1–3.5, 4.6 | Communication-security goals; explicit threat-model scope; passive/active network operations; denial of service. |
| `nist-sp-800-57pt1r5` | [NIST SP 800-57 Part 1 Rev. 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5) (May 2020) | 3, 5.2–5.5, 6.2, 7, 8.1–8.4, 9.5 | Key use and separation, metadata protection, compromise, lifecycle states, change, recovery, revocation, and destruction terminology. |
| `nist-sp-800-30r1` | [NIST SP 800-30 Rev. 1](https://doi.org/10.6028/NIST.SP.800-30r1) (September 2012) | 2.3, 3.2 Tasks 2-1 through 2-3, Appendices D–F | Separation of threat sources, capabilities, threat events, vulnerabilities, preconditions, and impacts. CCA-120 intentionally omits likelihood and risk scoring. |
| `rfc4949` | [RFC 4949](https://www.rfc-editor.org/rfc/rfc4949.html), FYI 36 (August 2007) | 1–3 and individual glossary entries | Terminology aid only. RFC 4949 is Informational, dated, author-oriented rather than an official IETF position, and may not cover newer security work; newer and more specific sources take precedence. |
| `rfc9180` | [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) (February 2022) | 9.1, 9.6, 9.7 | Example of explicitly scoped properties, compromise assumptions, domain/context separation, ordering, downgrade, replay, length, randomness, and other non-goals. HPKE is not selected or required. |
| `rfc9420` | [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) (July 2023) | 14–16, especially 16.4 and 16.6–16.10 | Example of state sequencing, metadata exposure, forward secrecy, post-compromise recovery, key reuse, and service-compromise assumptions. MLS is not selected or required. |

Source identifiers appear as bounded section references such as `rfc3552:section-3.3` or `nist-sp-800-57pt1r5:section-7`. Definitions remain protocol-neutral and mechanism-neutral; the repository copies no substantial source text.
