---
title: "Your first captured session"
description: "Get from agent setup to an inspectable activity record."
banner:
  content: "Development preview — starter documentation, not yet release-validated."
---

## Configure the repository

Complete the setup for [Claude Code](/secuarden-cli/agents/claude-code/) or [Codex](/secuarden-cli/agents/codex/).
Start a fresh agent conversation in that repository.

## Create a small, reviewable action

Ask the agent to read a repository file, make a small change, and run an appropriate
check. Review the resulting change before committing it.

## Inspect the evidence

From the repository, run:

```sh
secuarden status
secuarden events --last 20
secuarden report --since 24h
secuarden serve
```

The local dashboard is available at `http://127.0.0.1:8743` while `serve` is running.
You should see evidence from the new session. If it is absent, use the
[troubleshooting guide](/secuarden-cli/troubleshooting/).

## Confirm delivery separately

Use `secuarden verify-live --help` for your runtime's live-verification workflow.
A successful configuration check does not establish that a runtime delivered events.

Next: [inspect reports](/secuarden-cli/guides/reports/) or [monitor capture configuration](/secuarden-cli/integrity/monitoring/).
