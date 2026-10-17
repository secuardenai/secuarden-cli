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

After setup, run a real agent session in the configured repository that reads a file, makes a small change, and runs a command. Then inspect `secuarden status` and `secuarden events --last 20`. Setup alone does not establish that hooks are delivering events.

If no events arrive, check the selected repository and capture scope, the installed binary path, agent hook configuration, and any required Codex trust approval. After moving the main capture binary, use `secuarden hooks refresh`. Re-generate independent observation hooks separately if their executable path changes.


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
