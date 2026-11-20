# Capture configuration attestation

Configuration attestation records what Secuarden observes about its capture
configuration. It is independent of policy evaluation and never denies agent
operations. New `secuarden init` setups enable it by default; existing explicit
disables survive subsequent setup. Existing installations can opt in:

```sh
secuarden attestation enable --agent claude-code,codex
secuarden attestation watch
```

Select only agents you have configured. Omit `--agent` to select installed agents
on the first enable. Enabling again retains the original baseline and agents.

`watch` is a foreground monitor independent of agent hooks. It polls every 15
seconds, even if the hooks are removed. Run it under your process supervisor for
continuous observation. This release does not install an OS background service.
Without a running watcher, observations occur when you explicitly check or run
`status`, `report`, `session`, `chain`, `bom`, `verify`, or `gate`. The dashboard
reads the latest stored observation without changing it; an explicitly selected
alternate activity database does not inherit this machine's attestation.

```sh
secuarden attestation status
secuarden attestation check --json
secuarden attestation history --json
secuarden attestation verify
secuarden attestation disable
secuarden attestation enable
secuarden init --repo . --attestation=false
```

`check` returns nonzero for disabled, unconfigured, deviated, or unknown state.
`verify` checks stored history checksums; it does not require current configuration
to match. A disabled configuration can have a valid history. Disabling records a
permanent transition and stops configuration observation. Re-enabling compares
against the existing baseline, never silently accepts the current configuration,
and retains the disabled interval. Reports remain available while disabled.

## What is observed

The adapter observes user-level Claude Code and Codex hook definitions, required
capture events, matchers, hook command/arguments and execution settings, global
hook disabling, and configured Secuarden executable bytes. For Codex it also
observes the supported hook feature flags, per-hook enablement and project-trust
settings parsed by the existing adapter. Secuarden capture scope and privacy mode
are included. Configuration values and executable contents are stored as hashes;
credentials, raw commands and source code are not copied into this history.

JSON formatting and unrelated settings or unrelated hook additions do not change
the snapshot. Changes to the order of Secuarden hooks can change behavior and are
retained. New required integration settings should be added in the adapter.

Project-specific/managed overrides, runtime hook trust approval, runtime activation,
policy contents, and delivery of events are not certified by this snapshot. Keep
using `verify-live` for delivery checks. Missing files/hooks produce deviations;
unreadable or malformed inputs produce unknown observations.

## History and restoration

`~/.secuarden/attestation.db` contains a separate append-only SQLite event chain.
Its state includes a baseline digest, configuration status, last observed time,
last matching observation, and changed component labels. Each record covers the
previous record's hash. Operations verify existing checksums before appending,
and serialize concurrent processes with a database transaction.

A missing hook creates a deviation. A later matching snapshot creates a
restoration. Restoration only establishes the observed configuration at that
new timestamp; it never repairs earlier coverage or certifies tool delivery.
The previous observation timestamp bounds uncertainty about when a change began.
Intervals longer than 90 seconds between observations, including monitor downtime,
are recorded as observation gaps on the next enabled check. Backward clock changes
also produce gaps. These are local wall-clock observations, not trusted timestamps.

Reports show the current state and the full transition history, including earlier
deviations after restoration. This history is explicitly OS-user-wide and all-time,
not a claim that a particular repository, session, or commit was affected. Normal
unchanged checks stay in storage but are omitted from the displayed transition
history. The chain report includes this history and its latest hash in the optional
SaaS seal payload; ordinary session sync does not upload it.

For an intentional binary upgrade, capture-scope change, or agent addition:

```sh
secuarden attestation baseline --agent claude-code,codex --reason 'Approved capture upgrade'
```

Baseline replacement is explicit, requires a reason and a valid snapshot, and
retains earlier records. `init` and `hooks refresh` check before repairing existing
configuration; neither silently replaces an established baseline.

## Limits and configuration choice

Attestation is configurable because local users need an explicit way to stop its
observation and storage. Disabled is a visible state, not healthy configuration.
A gate's existing risk decision is unchanged; it displays attestation without
silently imposing a new coverage policy.

Polling can miss a disable-and-restore between checks. A developer can also stop
the monitor, delete this local database, change the clock, or rewrite records and
recompute their hashes. Local history is a checksum, not tamper-proof evidence.
An independently accepted SaaS seal strengthens the integrity claim for that
submitted snapshot but cannot recover observations that never occurred.

## Module boundaries

- `internal/attestation/model.go`: snapshots, state, events and report contracts.
- `internal/attestation/engine.go`: baseline, enable/disable, deviation, restoration
  and observation-gap transitions using an injected observer.
- `internal/attestation/store.go`: SQLite transactions and checksum validation.
- `internal/attestation/report.go`: read/reconcile facade and reporting semantics.
- `internal/agent/attestation.go`: semantic configuration observation, without
  invoking agent executables or executing hooks.
- `cmd/attestation.go`: lifecycle commands and independent foreground monitoring.

This separation lets future monitors and adapters reuse the same history contract
without coupling configuration attestation to the hook capture pipeline.
