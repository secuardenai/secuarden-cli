# Inspecting activity and verifying evidence

[Back to README](../README.md)

## Local activity commands

The CLI uses progressive disclosure so capture health, raw evidence, investigation,
and reporting remain separate:

- `secuarden status` — capture health, today's aggregate activity, evidence-backed attention findings, and recent sessions.
- `secuarden events` — chronological raw capture events. Combine `--last`, `--action`, `--session`, and `--sensitive`; add `--json` for scripts.
- `secuarden session <id>` — files, commands and outcomes, MCP calls, sensitive accesses, and failures for one session; supports `--json`.
- `secuarden report` — a 24-hour accountability report scoped to the current Git repository by default. Use `--repo`, `--all-repos`, `--absolute-paths`, `--limit`, `--md`, or `--json` as needed.
- `secuarden verify` — recompute the per-session SHA-256 chains and identify the exact session/sequence of modified evidence.
- `secuarden bom` — export file-write provenance, agent/model/developer context, risk reasons, content hashes, and integrity status as an AI-BOM JSON document.
- `secuarden gate` — return a non-zero exit code when AI-authored file changes meet a configurable deterministic risk threshold.
- `secuarden sync` — retry delivery of captured sessions that contain events not included in their last successful SaaS upload; use `--session <id>` to force a specific session.

Activity reports use already-redacted database fields. Reporting never rereads
files and does not make network calls. The [Git ledger and signed receipt workflows](ledger.md) have separate data sources and network behavior.

### Local dashboard

`secuarden serve` provides activity, agent, timeline, changed-file, command, and
attention summaries with drilldowns into captured events. File-change summaries
count confirmed successful changes, including multiple paths in a patch. Command
summaries distinguish passed, failed, and unknown outcomes. Unknown outcomes do
not count as success.

### Provenance integrity and CI gate

New events use a versioned canonical hash covering all persisted event evidence
and the preceding event hash. Repository, branch, model, and developer identity
are protected by a separate versioned session hash. Verification and export
operate entirely on the local redacted database.

Records created before complete hashing remain readable and are reported as
legacy, but the overall integrity result is invalid because their provenance
cannot receive complete integrity coverage retroactively. Verification,
AI-BOM export, and `secuarden gate` therefore fail closed.

```bash
# Verify evidence before an audit or export
secuarden verify

# Produce a portable AI Bill of Materials
secuarden bom --since 30d > secuarden-ai-bom.json

# GitHub Actions, GitLab CI, or any shell-based pipeline
secuarden gate --since 24h --fail-on high
```

Risk scoring is deliberately explainable and deterministic. It classifies paths
associated with identity, payments, secrets, cryptography, infrastructure, and
schemas; test and documentation paths receive a lower score. It is a governance
signal, not a SAST or license scanner.

## Example output

The following output is illustrative; formatting and counts depend on the version and captured sessions.

### Status

```
Secuarden Capture Agent <version>
Capture: Active · Claude Code
Database: ~/.secuarden/secuarden.db · 76 KB
Sync: Local only
Developer: alice <alice@example.com>

Today
  3 sessions · 52 actions · 14 files read · 6 files changed
  21 commands · 2 MCP calls · 1 sensitive access

Needs attention
  ⚠ Sensitive access   .env.local
  ⚠ Failed command     npm test · exit 1

Recent sessions
  18:04  verify-low-demo      23 actions · 4 files changed · 1 warning
  17:51  verify-low-demo      18 actions · 2 files changed · clean
  16:22  main                 11 actions · no changes · clean
```

### Events

```bash
$ secuarden events --last 3
2026-07-19T08:03:00Z  file_read         .env.local [SENSITIVE]
  status: success
2026-07-19T08:04:00Z  command_exec      npm test
  status: error · exit: 1
2026-07-19T08:05:00Z  mcp_tool_use      memory/create_entities
  status: success

$ secuarden events --action command_exec --session a1b2c3 --json
```

### Session

```text
Secuarden Session

Session ID: a1b2c3
Agent: Claude Code
Developer: alice <alice@example.com>
Repository: https://example.com/secuarden/secuarden-cli.git
Branch: main
Started: 2026-07-19T08:00:00Z
Ended: 2026-07-19T08:10:00Z
Duration: 10m0s
Events: 23

Actions
  command_exec         4
  file_read            12
  file_write           5
  session_end          1
  session_start        1

Sensitive accesses
  [SENSITIVE] file_read · .env.local

Failed, blocked, or rejected actions
  Failed command · npm test · exit 1
```

### Report

Reports are repository-scoped by default, so activity from unrelated projects in
the global database is not mixed together. Repository identities normalize common
SSH and HTTPS forms of the same Git remote without making a network request.

```bash
# Current Git repository, terminal lists limited to 10 entries each
secuarden report

# Select by local path, remote, or owner/repository identity
secuarden report --repo ../verifyflow-demo
secuarden report --repo git@github.com:example/verifyflow-demo.git
secuarden report --repo example/verifyflow-demo

# Cross-repository report, grouped by canonical repository identity
secuarden report --all-repos

# Restore full absolute paths or change the terminal list limit
secuarden report --absolute-paths --limit 25
```

Paths inside the selected repository are rendered relative to its verified Git
root. External reads and changes remain separate, and home-directory paths are
abbreviated with `~`. With `--all-repos`, internal paths are prefixed with the
repository name. Existing JSON path fields retain their original stored values;
additive repository/external collections and `repository`, `display_path`, and
`external` metadata describe classification and presentation.

```text
Secuarden accountability report
Repository: example/verifyflow-demo
Period: Last 24 hours · 18 Jul 13:52 – 19 Jul 13:52 AEST

Summary
  1 session · 16 actions
  1 repository file changed · 1 external file changed
  4 commands succeeded · 0 failed
  1 sensitive-path access

Agent activity
  Claude Code · 1 session · 16 actions

Files changed
  verifyflow/api.py

External activity
  Read     ~/Library/Application Support/Code/User/settings.json
  Changed  ~/other-project/generated.py

Sensitive-path access
  [SENSITIVE] 19 Jul 10:52 AEST · .env.example · session a1b2c3
```

## Browser dashboard

Run `secuarden serve`, then open http://127.0.0.1:8743. The server is read-only, binds only to loopback, serves embedded assets, and makes no external network requests. Use `--address 127.0.0.1:PORT` to select another local port.

