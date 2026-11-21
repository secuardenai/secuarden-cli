---
title: "Claude Code"
description: "Connect Claude Code to the local evidence recorder."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## Set up

New setups default to capturing supported sessions for the entire OS user.
To limit capture to this repository, add `--scope repo` to the setup command.
This changes the shared OS-user capture setting; rerunning setup otherwise
preserves existing scope and sync settings.

Install and launch Claude Code before configuring Secuarden. From the repository:

```sh
secuarden init --repo . --agent claude-code
```

Setup installs Secuarden hooks for the current OS user. Start a new agent session
and follow [your first captured session](/get-started/first-session/).

## After a CLI upgrade

```sh
secuarden hooks refresh
secuarden status
```

Refresh hooks using the stable installed binary. Confirm live delivery again after
changing the integration.

## Capture configuration

The [embedded contract](/integrity/contracts/) checks required shared hook
configuration. Project overrides and actual runtime delivery are outside that check.
