# Setup and repository configuration

[Back to README](../README.md)

### Repository configuration

```bash
# Enable sync on an existing install
secuarden init --repo . --api-key sec_xxxx

# Re-run setup while preserving existing repository sync settings
secuarden init --repo .

# Use a self-hosted or staging instance
secuarden init --repo . --api-key sec_xxxx --api-url https://secuarden.example.com
```

Setup always requires `--repo PATH`, including when you are already inside a Git
repository. API keys and server URLs are stored per canonical repository path in
`~/.secuarden/config.json`, outside the worktree. Configure each repository
explicitly; user-wide API keys are not a fallback. Omitting `--api-key` preserves
an existing integration and does **not** disable sync.

Capture scope is separate from repository sync configuration. New configurations
default to `--scope all`; use `--scope repo` to limit capture to the selected
repository, or `--scope approved` with an allowlist. Existing scope is preserved
unless changed explicitly.

### Claude Code and Codex setup

```bash
# Select an agent explicitly
secuarden init --repo . --agent claude-code
secuarden init --repo . --agent codex

# Explicitly allow Secuarden to enable the Codex hooks feature
secuarden init --repo . --agent codex --enable-codex-hooks

# Refresh existing main capture hooks after moving or upgrading the binary
secuarden hooks refresh
```

The default `--agent auto` configures detected supported agents. Codex support
depends on the installed runtime's hook capabilities, configuration, and trust.
Installation alone does not establish working capture. Follow setup diagnostics,
review hook commands in Codex when prompted, then use `secuarden status` and
`secuarden events` to check delivery. Hook refresh does not grant trust.

Run setup with a binary installed at a stable path. Hooks reference the executable
that installs them; avoid using `go run` for setup or hook installation.

## Checking capture

`init` arms a 15-minute live-verification window and returns with verification
pending. This means hooks were configured, not that a client delivered evidence.
Follow the [live-verification procedure](live-capture-verification.md): arm a
fresh window, start a new conversation in the intended repository, perform a tool
action, and check that conversation's exact session ID. Check the reported stage;
a pending result can return exit status zero.

For VS Code, open the intended repository folder in the intended window. Save
work and finish tasks before reloading that window if configuration may not have
loaded. Review hook approvals if presented, then arm a fresh verification window.
Do not use an unrelated desktop conversation or select a session solely because
it is the newest in the database.

Keep the configured executable at a persistent path. After moving or upgrading
it, run `secuarden hooks refresh` with the intended installed binary. Refresh does
not grant trust. Re-generate independent observation hooks separately if their
executable path changes.

### Interpreting status

- **Verification pending:** no successful current verification has been established.
- **Last verified:** persisted request/result evidence was observed for the named
  session and repository. An idle client is not unhealthy merely because this
  timestamp is old.
- **Stale:** configuration, executable, or detectable runtime changes mean the
  historical result no longer verifies the current setup. Arm and complete a new
  check after activation and trust review as needed.
- **Configured command missing / not executable:** repair the installed binary
  path or permissions and refresh hooks before repeating live verification.

If no events arrive, check repository scope, hook configuration, and client
activation/trust. Scope-skip counters aggregate multiple sessions; they cannot
identify which conversation was skipped. See the guide's
[incomplete results](live-capture-verification.md#incomplete-results).


## Uninstall

```bash
# Remove main agent capture hooks, keep captured data
secuarden uninstall

# Also delete ~/.secuarden and its captured data
secuarden uninstall --purge
```

The independent observation hooks and repository receipt pre-push hooks have
separate lifecycles. Disable observation capture with `secuarden ledger capture disable`
and select `secuarden init --repo . --receipt-mode explicit` to turn off automatic receipts
before purging local data.
