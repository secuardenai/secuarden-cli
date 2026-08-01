# Security Policy

Secuarden takes the security and privacy of its local capture data seriously. We
welcome responsible reports that help protect Secuarden users.

## Supported versions

Security fixes are provided for the latest published release of
`secuarden-cli`. Users should reproduce and verify reports against the latest
release before submitting them.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Earlier releases | No |

## Reporting a vulnerability

Do not open a public GitHub issue, discussion, or pull request for a suspected
security vulnerability.

Report vulnerabilities privately through
[GitHub Private Vulnerability Reporting](https://github.com/secuardenai/secuarden-cli/security/advisories/new).

Include enough information for us to understand and reproduce the issue:

- A concise description of the vulnerability and its impact
- The affected Secuarden version, operating system, and architecture
- Required configuration, including whether optional SaaS sync is enabled
- Reproduction steps or a minimal proof of concept
- Relevant logs or output after removing credentials and personal information
- Any suggested mitigation or remediation

Never include real API keys, access tokens, credentials, sensitive source code,
unredacted local database contents, or another person's data. Use synthetic test
data and explicit placeholders.

We will review the report, confirm whether it is in scope, and coordinate next
steps with the reporter. Remediation and disclosure timelines depend on the
severity, complexity, and affected users. Please allow us a reasonable
opportunity to investigate and release a fix before public disclosure.

## Security issues in scope

Examples include vulnerabilities that could cause:

- Captured secrets or sensitive content to bypass redaction or suppression
- Unintended disclosure of local SQLite data, configuration, API keys, or hook
  payloads
- Incorrect file permissions, unsafe path handling, or unauthorized file access
- Commands or tool output to be executed rather than treated as captured data
- Hook installation or processing to modify unintended configuration or execute
  attacker-controlled code
- Optional sync to transmit data beyond the documented payload or use an
  insecure transport
- JSON, Markdown, or terminal output to expose information not already present
  in redacted stored fields
- Release archives, checksums, or installation behavior to deliver an
  unexpected binary or modify unintended files
- A denial of service with a practical security impact against normal CLI use

Reports about the Secuarden SaaS service may use the same private channel, but
must clearly identify the affected service and distinguish it from the public
CLI.

## Generally out of scope

The following are normally not treated as vulnerabilities in this repository:

- Product questions, feature requests, or ordinary functional bugs
- Findings that affect only unsupported or locally modified builds
- Automated scanner output without a reproducible impact
- Dependency advisories without an exploitable path in Secuarden
- Social engineering, physical attacks, or attacks requiring access to an
  already-compromised workstation without additional impact
- Vulnerabilities in Claude Code, Git, GitHub, SQLite, or another third-party
  product that do not arise from Secuarden's use of that product
- Availability testing that creates excessive traffic or disrupts services

Report vulnerabilities in third-party products directly to the appropriate
maintainer. If Secuarden's integration makes a third-party issue exploitable,
explain that connection in the private report.

## Safe research expectations

When investigating Secuarden:

- Use systems, repositories, accounts, and data you own or are authorized to test
- Keep testing local where possible and avoid accessing another user's data
- Do not degrade services, destroy data, establish persistence, or exfiltrate
  information
- Stop testing once you have enough evidence to demonstrate the issue
- Protect vulnerability details and any accidentally encountered data
- Follow applicable laws and the terms of the services involved

Good-faith reports that follow this policy help us improve Secuarden for
everyone.
