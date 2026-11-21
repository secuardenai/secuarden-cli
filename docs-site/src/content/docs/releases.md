---
title: "Versions and upgrades"
description: "Commands available in published releases and the corrective release candidate."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## Version compatibility

These guides target the **v0.8.1 release candidate**. It is not published yet.

| Version | Core capture and reports | Configuration attestation | Experimental chain |
| --- | --- | --- | --- |
| v0.7.0 | Available | Unavailable | Unavailable |
| Published v0.8.0 | Available | Unavailable | Unavailable |
| v0.8.1 candidate | Available | Available | Available |

The published v0.8.0 tag points to the same source commit as v0.7.0
(`6e8a280`). Its version label changed, but it does not contain the later
attestation and chain implementation. Do not use the version number alone as
proof those commands are present. Existing published tags will remain unchanged.

[Published releases](https://github.com/secuardenai/secuarden-cli/releases)
are the source for downloadable binaries. The installer selects the latest
published release, so it cannot install this candidate before publication.

## Upgrade after the corrective release is published

Install the intended release and check its version and commands before refreshing:

```sh
secuarden version
secuarden attestation contracts
secuarden chain --help
secuarden hooks refresh
secuarden status
secuarden attestation check
```

If attestation reports `not_configured`, enable it for your configured agents.
An explicit previous disable remains disabled unless you enable it again.
Repeat the [fresh-session live check](/get-started/first-session/) after refreshing
hooks. Contract checks establish configuration, not runtime delivery.

## Validation boundary

Automated tests and command-help checks do not substitute for a fresh live agent
session. SaaS seal acceptance, platform-specific runtime trust, and complete
capture must not be inferred from a passing local build.
