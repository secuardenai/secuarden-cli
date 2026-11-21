---
title: "Versions and upgrades"
description: "Keep documentation aligned with the CLI you actually installed."
banner:
  content: "Development preview — starter documentation, not yet release-validated."
---

## Development preview

These starter pages describe work in the development checkout. They are not a
published release promise. Check `secuarden version` and command help before
following development-only instructions.

[Published CLI releases](https://github.com/secuardenai/secuarden-cli/releases)
remain the source for downloadable releases and their notes.

## Upgrade workflow

Install the intended CLI release, then refresh hooks using that binary:

```sh
secuarden hooks refresh
secuarden status
```

Repeat live verification. For versions with contract attestation, run
`secuarden attestation check` and inspect the recorded contract transition.

## Documentation publishing

Release-specific guides and an upgrade compatibility matrix will be added as the
site is prepared for production. This scaffold is intentionally marked as a
preview and excluded from search-engine indexing.
