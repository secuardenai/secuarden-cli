---
title: "Claude Code"
description: "Connect Claude Code to the local evidence recorder."
banner:
  content: "Development preview — starter documentation, not yet release-validated."
---

## Set up

Install and launch Claude Code before configuring Secuarden. From the repository:

```sh
secuarden init --repo . --agent claude-code
```

Setup installs Secuarden hooks for the current OS user. Start a new agent session
and follow [your first captured session](/secuarden-cli/get-started/first-session/).

## After a CLI upgrade

```sh
secuarden hooks refresh
secuarden status
```

Refresh hooks using the stable installed binary. Confirm live delivery again after
changing the integration.

## Capture configuration

The [embedded contract](/secuarden-cli/integrity/contracts/) checks required shared hook
configuration. Project overrides and actual runtime delivery are outside that check.
