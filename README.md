# secuarden cli

[![Tests](https://github.com/secuardenai/secuarden-cli/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/secuardenai/secuarden-cli/actions/workflows/test.yml?query=branch%3Amain)
[![Latest release](https://img.shields.io/github/v/release/secuardenai/secuarden-cli)](https://github.com/secuardenai/secuarden-cli/releases/latest)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**Local flight recorder and cryptographic provenance CLI for AI coding agents.**

`secuarden` silently records what your coding agent touched, which prompts and tools drove each file change, and verifies the integrity of your AI-generated diffs—stored 100% locally in SQLite with zero cloud dependencies.

![secuarden CLI demo](docs/demo/secuarden-terminal-demo.gif)

## Why use it locally?

- **See what the agent actually did:** Inspect every file read, shell command, and edit made during Claude Code and Codex sessions (`secuarden events`, `secuarden session`).
- **Verify diff integrity:** Every session and change is chained with cryptographic hashes and anchored to Git (`secuarden verify`, `secuarden ledger`).
- **Catch risky changes before commit or CI:** Run local risk thresholds (`secuarden gate`) and AST-based route protection (`secuarden policy`) to flag or block unsafe agent edits.
- **Export tamper-evident AI BOMs:** Generate a JSON Bill of Materials (`secuarden bom`) or full accountability report (`secuarden report`) for pull requests and audits.
- **Local web inspector:** Run `secuarden serve` to browse your full session timeline, events, and diffs at `http://127.0.0.1:8743`.
- **Offline & private by default:** Everything lives in `~/.secuarden/secuarden.db`. No account, no telemetry, no API key required.

## Quickstart

### 1. Install
```bash
curl -fsSL https://install.secuarden.ai | sh
# or via Go
go install github.com/secuardenai/secuarden-cli/cmd/secuarden@latest
```

### 2. Hook into your agent & check status

```bash
secuarden init --repo .
secuarden status
```

### 3. Inspect a session in your terminal (or browser)

```bash
+++++++++++++++++++++++++++++
Secuarden Capture Agent 0.7.0
+++++++++++++++++++++++++++++

+--------------------------------------------------------------------------------+
| Capture:              | Configured · Claude Code, Codex                        |
| Live verification:    | claude-code: verified                                  |
|                       | codex: verified                                        |
| Database:             | ~/.secuarden/secuarden.db · 11.5 MB                    |
| Sync:                 | Disabled (local-only)                                  |
| Capture scope:        | All supported projects for this OS user                |
| Receipt mode:         | Automatic (local ledger)                               |
| Last receipt:         | generated · refs/heads/feature/auth-middleware         |
| Current repository:   | ~/projects/api-service                                 |
| Claude Code hooks:    | configured                                             |
| Codex hooks:          | configured                                             |
| Last persisted event: | - Claude Code: 2026-11-20T19:24:56Z                    |
|                       | - Codex: 2026-11-20T21:35:05Z                          |
| Developer:            | alex <alex@example.com>                                |
| Privacy:              | redacted_content                                       |
+--------------------------------------------------------------------------------+

Today
  8 sessions · 56 actions · 14 files read · 4 files changed
  10 commands · 1 MCP call · 0 sensitive accesses

Needs attention
  None detected in today's captured activity.

Recent sessions
  08:35  feature/auth-middleware     18 actions · 3 files changed · verified
  08:15  feature/policy-enforcement  29 actions · 1 file changed  · verified
  06:24  fix/token-refresh            9 actions · no changes     · verified

Run `secuarden events` for the raw event log.
Run `secuarden report` for the full accountability report.
```

### Want a visual timeline? Launch the local UI:

```bash
secuarden serve

Secuarden local evidence is available at http://127.0.0.1:8743
Read-only · local device only · press Ctrl+C to stop
```

## Core Local Commands

| Command | Purpose |
| :--- | :--- |
| `secuarden init --repo .` | Install Secuarden hooks and set up capture for a repository. |
| `secuarden status` | Show capture health, today's activity, and items needing attention. |
| `secuarden verify-live --repo . --agent codex --client cli` | Verify a fresh agent tool round-trip persisted locally. |
| `secuarden events --last 20` | Show the chronological raw event log. |
| `secuarden session SESSION_ID` | Investigate one captured session. |
| `secuarden ledger` | Build and inspect Git-anchored change records. |
| `secuarden gate` | Fail pre-commit or CI checks when captured AI changes exceed a risk threshold. |
| `secuarden bom` | Export a tamper-evident AI Bill of Materials as JSON. |
| `secuarden report` | Generate an aggregated local accountability report. |
| `secuarden verify` | Verify the integrity of the stored audit trail for a repository. |
| `secuarden serve` | Open a local read-only dashboard server (`127.0.0.1:8743`). |


### How It Works Locally

1. **Capture**: Lightweight agent hooks log tool invocations and file edits in real time without slowing down your terminal.
2. **Store**: Events are written to a local SQLite database (~/.secuarden/secuarden.db) with cryptographic hash chaining.
3. **Verify & Export**: Query your history anytime via CLI, local web UI, or export an auditable context bom artifact when you need to attach proof to a PR.

### Optional: Team & Cloud Sync

secuarden-cli works completely standalone. If your organization uses [Secuarden Cloud](https://app.secuarden.com/) for multi-repo visibility and centralized policy enforcement, run secuarden auth login to sync local receipts.


## Guides

- [Setup, agent configuration, capture checks, and uninstall](docs/setup.md)
- [Live capture verification and troubleshooting](docs/live-capture-verification.md)
- [Activity commands, dashboard, reports, and verification](docs/activity.md)
- [Git ledger, Codex observations, and signed receipts](docs/ledger.md)
- [Local policy enforcement v0.1](docs/policy-v0.1.md)
- [Architecture and evidence contracts](docs/architecture.md)

## Contributing

Documentation fixes, synthetic hook fixtures, redaction improvements, and agent
integrations are welcome. Open an issue before starting significant work.

Building requires Go 1.25 or newer and Git. From this checkout:

```bash
make build
make test
./bin/secuarden --help
```

Use a stable installed binary for setup. `make install` copies it to
`/usr/local/bin/secuarden` and requires write access there. After upgrading,
run `secuarden hooks refresh` so installed hooks use that path. Avoid `go run`
for setup or hook installation, because hooks store the executable's path.

## License

[Apache 2.0](LICENSE). Built by [Secuarden AI](https://secuarden.ai).
