---
title: "Codex"
description: "Set up a compatible Codex runtime and confirm capture."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## Check runtime support

Codex support depends on the installed runtime's hook capabilities and required
trust. Installing the CLI alone does not establish that integration is active.

## Set up

New setups default to capturing supported sessions for the entire OS user.
To limit capture to this repository, add `--scope repo` to the setup command.
This changes the shared OS-user capture setting; rerunning setup otherwise
preserves existing scope and sync settings.

From your repository:

```sh
secuarden init --repo . --agent codex
```

If setup reports that the supported hooks feature is disabled, explicitly enable it:

```sh
secuarden init --repo . --agent codex --enable-codex-hooks
```

Complete any trust approval in Codex, then start a new conversation. Follow
[your first captured session](/get-started/first-session/).

## Check delivery

```sh
secuarden verify-live --help
secuarden status
```

The client label and exact session identifier matter for live verification. A
pending verification window is not a successful round-trip.
