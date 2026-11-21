---
title: "Monitor capture configuration"
description: "Retain observed violations, restorations, and monitoring gaps."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## Enable and observe

```sh
secuarden attestation enable
secuarden attestation watch
```

Specify `--agent claude-code` or `--agent codex` when enabling a specific integration.
The watcher runs in the foreground, independently of agent hooks. It checks every
15 seconds by default. No OS background service is installed automatically.

## Inspect the record

```sh
secuarden attestation status
secuarden attestation history --json
secuarden attestation verify
```

| State | Meaning |
| --- | --- |
| `satisfied` | Observed configuration meets the embedded contract. |
| `violated` | At least one required condition fails. |
| `unknown` | Configuration could not be fully assessed or the observation is stale. |
| `disabled` | Checks are disabled; history remains. |
| `not_configured` | Attestation has not been initialized for this OS user. |
| `legacy_unverified` | Older snapshot history has not yet been evaluated against a contract. |

Restoring configuration appends a restoration; it does not erase the deviation.
Observation gaps over 90 seconds are recorded on the next enabled check.

## Disable checks

```sh
secuarden attestation disable
```

Disabling records a transition. Re-enabling does not approve a failing configuration.
Polling may miss changes between checks, and the machine owner can modify local
history. These are observable records, not tamper-proof enforcement.
