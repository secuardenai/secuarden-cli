---
title: "Your first captured session"
description: "Get from agent setup to an inspectable activity record."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## Configure the repository

Complete the setup for [Claude Code](/agents/claude-code/) or [Codex](/agents/codex/).
Before starting the conversation, arm the live check below.

## Start live verification before the conversation

For Codex in the CLI, run:

```sh
secuarden verify-live --repo . --agent codex --client cli
```

This starts a 15-minute window and returns nonzero while verification is pending.
Use `--agent claude-code` for Claude Code and select your actual client label
(`cli`, `vscode`, `desktop`, or `unknown`). The label is your declaration, not
independently verified application identity.

Start a **new** conversation in this repository. Ask the agent to read a harmless
file, make a small reviewable change, and run an appropriate check. If local policy
blocks shell commands, use an allowed read to confirm delivery and run tests
manually; do not describe manual tests as agent-executed.

Obtain that conversation's exact session/thread ID from the client or its local
record. Replace `EXACT_SESSION_ID` below; do not guess from unrelated recent activity.

```sh
secuarden verify-live --repo . --agent codex --client cli --session EXACT_SESSION_ID --wait 60s
```

Keep the same agent/client selection. Exit zero confirms a persisted matching tool
request and result from the fresh session. It does not prove tool success,
complete capture, stored integrity, or upload status. An expired window requires
arming again and starting another new conversation.

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
[troubleshooting guide](/troubleshooting/).

## Check stored evidence separately

```sh
secuarden session EXACT_SESSION_ID
secuarden verify
```

Review outcomes and checkpoint completeness in the session. Successful live
delivery and stored integrity are separate checks; neither proves complete capture.

Next: [inspect reports](/guides/reports/) or [monitor capture configuration](/integrity/monitoring/).
