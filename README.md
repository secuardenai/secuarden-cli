# secuarden-cli

**Know exactly what your AI coding agent did — every file read, every command run, every secret touched. Get immediate risk feedback when a session ends.**

<!-- TODO: Replace with actual terminal recording -->
<!-- ![secuarden demo](docs/demo.gif) -->

```bash
$ secuarden init --api-key sec_xxxx
✓ Claude Code detected
✓ SaaS sync enabled — session feedback will appear in terminal
✓ Hooks installed (PreToolUse, PostToolUse, SessionStart, SessionEnd)
✓ Database created at ~/.secuarden/secuarden.db
✓ Developer identity: alice <alice@company.com>

# ... use Claude Code normally across multiple sessions ...

── Secuarden ──────────────────────────────────────
⚑ REVIEW REQUIRED — 'feat/auth-refactor' (2 session(s), high risk).
  Triggered: AI-authored authentication changes. Assign AppSec reviewer.
───────────────────────────────────────────────────
```

## Why this exists

AI coding agents read your files, run shell commands, access environment variables, and modify your codebase — often 50+ actions per session. When your SOC 2 auditor asks *"who authorized this change and what did the AI actually do?"* nobody can answer. Git logs show code was committed. They don't show the agent read your `.env`, executed 47 shell commands, and rewrote 12 files in 90 seconds.

secuarden-cli is a passive, zero-config capture agent that records every action your AI coding agent takes. No dashboards, no analytics, no opinions — just a tamper-aware local ledger of what actually happened, with secrets automatically scrubbed before storage.

## Features

- **One-command install** — `secuarden init` detects your agent, installs hooks, creates the database. Add `--api-key` once to enable SaaS sync.
- **Captures everything** — file reads, file writes, shell commands, MCP tool calls, subagent spawns. Every action gets a structured event with timestamp, developer identity, and session context.
- **Immediate risk feedback** — when SaaS sync is enabled, risk is evaluated across the full branch history (all sessions, not just the last one) and printed in the terminal the moment a session ends.
- **AI Change Set tracking** — multiple sessions on the same branch are automatically grouped into one provenance unit. Risk accumulates and is re-evaluated after every session, so you see the full picture before opening a PR.
- **Secrets never hit disk** — two-layer privacy: sensitive file detection (`.env`, `*.pem`, `.ssh/*`) suppresses all content. Content redaction scrubs API keys, tokens, JWTs, and credentials from commands and output. What gets stored is the action, not the secret.
- **Structured event schema** — every event follows a [documented JSON schema](schema/secuarden-event.schema.json) designed for downstream compliance tooling, SIEM ingestion, or your own analysis.
- **Developer identity** — each session records who ran it (git config + OS user), not just what happened.
- **Local-first, opt-in sync** — all data stays in SQLite by default. SaaS sync and feedback require an explicit `--api-key`.

## Quickstart

### Local-only (no account required)

Captures all agent activity to local SQLite. Nothing leaves your machine.

```bash
# Install
curl -fsSL https://install.secuarden.ai | sh
# or: brew install secuarden/tap/secuarden

# Set up
secuarden init

# Use Claude Code normally — events are captured automatically
claude "refactor the auth module"

# See what was captured
secuarden status
```

### With SaaS sync (recommended for teams)

Enables the AI Change Set evaluator and delivers risk feedback to your terminal after every session.

```bash
# Install
curl -fsSL https://install.secuarden.ai | sh

# Set up with your Secuarden API key
secuarden init --api-key sec_xxxx

# Use Claude Code normally across one or more sessions on a branch
claude "implement the payment webhook handler"

# When the session ends you'll see:
# ── Secuarden ──────────────────────────────────────
# ⚑ REVIEW REQUIRED — 'feat/payments' (1 session(s), high risk).
#   Triggered: AI-authored payment/billing changes. Attach test evidence.
# ───────────────────────────────────────────────────
```

Get an API key at [secuarden.ai](https://secuarden.ai). Your repo must be connected in the Secuarden dashboard for change set history to persist across sessions.

### Switching modes

```bash
# Enable sync on an existing install
secuarden init --api-key sec_xxxx

# Disable sync (revert to local-only)
secuarden init

# Use a self-hosted or staging instance
secuarden init --api-key sec_xxxx --api-url https://secuarden.example.com
```

### Using the IDE extension (VS Code / JetBrains)

When you run Claude Code through the IDE extension rather than the terminal, hook output isn't shown in a visible terminal. The session is still captured to local SQLite and — if sync is enabled — the changeset is still evaluated. The feedback is written to `~/.secuarden/last-feedback.json` after every session.

To see it, open any terminal and run:

```bash
secuarden status
```

```
Secuarden Capture Agent v0.1.0

Status: Active
Database: ~/.secuarden/secuarden.db (284 KB)
Sessions: 7 | Events: 312
Developer: alice <alice@company.com>
Sync: enabled (https://app.secuarden.ai)

Last 5 events:
  2026-05-29 10:44:58  file_write    src/auth/session.ts
  2026-05-29 10:44:59  file_write    src/auth/oauth.ts
  2026-05-29 10:45:01  command_exec  npm test (exit: 0)
  2026-05-29 10:45:03  file_read     .env.local [SENSITIVE]
  2026-05-29 10:45:05  command_exec  git commit -m "refactor auth"

── Last changeset evaluation ────────────────────────
   2026-05-29 10:45:06  (just now)
   ⚑  REVIEW REQUIRED — 'feat/auth-refactor' (2 session(s), high risk).
      Triggered: AI-authored authentication changes. Assign AppSec reviewer.
─────────────────────────────────────────────────────
```

## Example Output

After a typical Claude Code session where you ask it to refactor an authentication module, `secuarden status` might show:

```
Secuarden Capture Agent v0.1.0
Status: Active
Database: ~/.secuarden/secuarden.db (284 KB)
Sessions: 1 | Events: 43

Last 5 events:
  2026-05-28 10:41:12  file_read     src/auth/session.ts
  2026-05-28 10:41:14  file_read     .env.local [SENSITIVE]
  2026-05-28 10:41:15  command_exec  npm run test:auth (exit: 1)
  2026-05-28 10:41:18  file_write    src/auth/session.ts (+34/-12)
  2026-05-28 10:41:20  command_exec  npm run test:auth (exit: 0)
```

Behind the scenes, each event is a structured record in SQLite:

```json
{
  "schema_version": "1.0.0",
  "id": "a1b2c3d4-...",
  "session_id": "e5f6a7b8-...",
  "sequence": 17,
  "timestamp": "2026-05-28T10:41:14Z",
  "source": "secuarden-cli",
  "agent_name": "claude-code",
  "hook_phase": "post",
  "action_type": "file_read",
  "tool_name": "Read",
  "is_sensitive": true,
  "file_path": ".env.local",
  "content_hash": "sha256:a3f2b8c1...",
  "redacted_fields": ["content"],
  "developer_email": "gaurab@example.com",
  "os_user": "gaurab",
  "raw_event_hash": "sha256:d4e5f6..."
}
```

## Use Cases

### For security & GRC teams
Your engineering team adopted AI coding tools. Your auditor is going to ask about it. secuarden-cli gives you the raw evidence trail — what the agent did, which files it touched, which commands it ran — so you're not scrambling when CC8.1 comes up in your next SOC 2 audit.

### For platform engineering teams
You rolled out Claude Code or Cursor to 50 engineers. You have no visibility into what these agents are doing across your codebase. secuarden-cli gives you structured, queryable data on agent behavior without slowing anyone down.

### For individual developers
You prompted the agent to "fix the login bug" and it touched 15 files. Which ones? Did it read your `.env`? Did it run anything unexpected? `secuarden status` tells you in 2 seconds.

### For compliance automation
The [Secuarden Event Schema](schema/secuarden-event.schema.json) is designed for downstream ingestion. Pipe events to your SIEM, feed them to compliance tooling, or build your own analysis. The schema is documented, versioned, and stable.

## Comparison

| | secuarden-cli | [Gryph](https://github.com/safedep/gryph) |
|---|---|---|
| **Primary purpose** | Governance evidence trail | Developer debugging & observability |
| **Secret scrubbing** | Two-layer: sensitive file detection + content redaction with named patterns | Content redaction |
| **Developer identity** | Git config + OS user per session | Not captured |
| **Event schema** | Documented JSON schema, versioned, designed for compliance tooling ingest | Internal schema, JSONL export |
| **Redaction transparency** | `[REDACTED:bearer_token]` — you see what was scrubbed | Content replaced silently |
| **Design philosophy** | Minimal CLI. Capture and store. Analysis happens elsewhere. | Full-featured: query, filter, diff, stats, session replay |
| **Agent support** | Claude Code (more coming) | Claude Code, Cursor, Windsurf, Gemini CLI, Copilot, OpenCode |
| **Language** | Go | Go |
| **License** | Apache 2.0 | Apache 2.0 |

Gryph is excellent if you want a local developer debugging tool with rich querying. secuarden-cli is built for a different job: producing structured, privacy-safe, identity-tagged evidence that downstream compliance and security tooling can consume.

## Supported Agents

| Agent | Status |
|---|---|
| Claude Code | ✅ Supported |
| Cursor | 🗓️ Planned |
| GitHub Copilot | 🗓️ Planned |
| Windsurf | 🗓️ Planned |
| OpenAI Codex | 🗓️ Planned |

## Roadmap

- [x] Claude Code capture agent
- [x] Sensitive file detection
- [x] Content redaction with named patterns
- [x] Developer identity capture
- [x] Documented event schema (v1.0.0)
- [x] SaaS sync with `--api-key` switch
- [x] AI Change Set — multi-session risk aggregation per branch
- [x] Immediate terminal feedback on session-end
- [x] `secuarden status` shows last changeset evaluation (works in IDE extensions)
- [ ] Cursor support
- [ ] Copilot support
- [ ] Gryph event adapter (ingest Gryph JSONL into Secuarden schema)
- [ ] Event export to SIEM (Splunk, Elastic, Datadog)

## Event Schema

The [Secuarden Event Schema](schema/secuarden-event.schema.json) is the contract between capture agents and any downstream consumer. It's a superset of what Gryph captures, extended with:

- `developer_name`, `developer_email`, `os_user`, `machine_id` — identity fields
- `intent_summary` — the developer's prompt/objective
- `redacted_fields` — transparency about what was scrubbed
- `raw_event_hash` — SHA-256 of the raw hook input for integrity verification
- `compliance_hints` — reserved for downstream compliance tooling (never populated by capture agents)
- `source` and `source_version` — multi-source support from day one

The schema is versioned and stable. Breaking changes will get a major version bump.

## How It Works

### Local-only mode

```
┌──────────────────────────────┐
│        Claude Code           │
│  PreToolUse / PostToolUse    │
│  SessionStart / SessionEnd   │
└──────────┬───────────────────┘
           │ stdin (JSON)  async hooks
           ▼
┌──────────────────────────────┐
│     secuarden hook           │
│                              │
│  1. Parse event              │
│  2. Detect sensitive files   │
│  3. Redact secrets           │
│  4. Capture identity         │
│  5. Write to SQLite          │
└──────────┬───────────────────┘
           │
           ▼
  ~/.secuarden/secuarden.db
```

### With SaaS sync (`--api-key`)

The SessionEnd hook runs synchronously so the terminal stays open for feedback. All other hooks remain async and never slow down the session.

```
Claude Code session ends
           │
           ▼
  secuarden hook session-end  (synchronous)
           │
           ├─► Write to local SQLite  (always)
           │
           └─► POST /api/agent-ledger/session-sync
                       │  Bearer: sec_xxxx
                       ▼
              Secuarden SaaS
                       │
                       ├─ Upsert AgentSession
                       ├─ Resolve repo from git remote URL
                       ├─ Merge into AI Change Set
                       │    (union of all sessions on this branch)
                       └─ Evaluate policies → decision + risk level
                                  │
                                  ▼
              ── Secuarden ──────────────────────────────────
              ⚑ REVIEW REQUIRED — 'feat/auth-refactor' …
              ───────────────────────────────────────────────
              (printed to terminal before Claude Code exits)
```

### AI Change Set

Multiple Claude Code sessions working on the same branch are automatically grouped into one **AI Change Set**. Risk is evaluated across the full accumulated set of files — not just the last session.

```
Session 1 (Mon)  →  touches src/auth/session.ts
Session 2 (Tue)  →  touches src/auth/oauth.ts
Session 3 (Wed)  →  touches src/payment/webhook.ts
                              │
                              ▼
              AI Change Set: feat/payment-refactor
              Files touched: 3 auth + 1 payment path
              Decision:      require_evidence  (high risk)
              Sessions:      3
```

This matters because risk accumulates over days. Evaluating only the last session would miss that the branch already touched auth code two days ago.

## Data & Privacy

- **Local by default.** Without `--api-key`, nothing leaves your machine. No network calls, no telemetry, no analytics.
- **Opt-in sync.** When `--api-key` is set, only the session summary (files edited, branch name, event count) is sent to Secuarden. Raw code diffs and command output are never uploaded.
- **Sensitive files** (`.env`, `*.pem`, `.ssh/*`, credentials) — file paths are recorded but content is never stored or uploaded.
- **Content redaction** — API keys, tokens, JWTs, bearer tokens, and credentials are scrubbed from shell commands and output before storage. Redacted content is replaced with `[REDACTED:<pattern_name>]`.
- **Your coding session is not slowed down.** All hooks except SessionEnd run asynchronously. SessionEnd is synchronous only to deliver feedback; it exits in under a second with or without sync enabled.

## Uninstall

```bash
# Remove hooks, keep captured data
secuarden uninstall

# Remove everything including captured data
secuarden uninstall --purge
```

## Contributing

Contributions welcome. The most impactful areas:

1. **New agent support** — adding hooks for Cursor, Copilot, Windsurf. See `internal/agent/claudecode.go` for the pattern.
2. **Redaction patterns** — new vendor-specific secret patterns in `internal/privacy/redact.go`.
3. **Test fixtures** — realistic hook JSON samples in `test/fixtures/`.

```bash
# Build
make build

# Test
make test

# Install locally
make install
```

Please open an issue before starting significant work so we can align on approach.

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

Built by [Secuarden](https://secuarden.ai). The capture agent is open source. The compliance intelligence platform is coming.