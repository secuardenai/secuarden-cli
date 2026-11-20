# Embedded capture contracts

Secuarden ships a versioned minimum capture contract for each supported adapter
inside the CLI binary. The installer and attestation checker use the same
`internal/capturecontract` definitions. A machine's existing configuration does
not define compliance, and a developer cannot accept broken hooks as a new gold
state.

```sh
secuarden attestation contracts
secuarden attestation enable --agent claude-code,codex
secuarden attestation watch
```

Select agents you have configured. On first enable, omitting `--agent` selects
installed integrations. Enabling again retains existing adapters; explicitly
selecting additional adapters adds coverage and records the transition. It does
not silently remove an existing adapter because its hooks have disappeared.

New `secuarden init` setups enable attestation by default. Subsequent setup
preserves an explicit disable. `--attestation=false` disables checks. Installation
is checked against the embedded contract, rather than captured as an acceptable
snapshot. Failed initial checks remain recorded and monitoring stays enabled so
restoration can be observed.

## Contract requirements

Both adapters require SessionStart, UserPromptSubmit, PreToolUse, PostToolUse and
SessionEnd capture. Codex also requires PermissionRequest and Stop. For each event:

- Exactly one Secuarden command handler must be configured.
- Its handler and arguments must match the embedded definition. Extra arguments,
  shell wrappers, redirection and unsupported command syntax are rejected.
- Its matcher must cover all required events (omitted, empty or `*`), and neither
  hook nor matcher group may explicitly disable capture.
- Its explicit timeout must meet the supported minimum in the contract (5 seconds
  for most hooks; 10 for SessionEnd and Codex Stop). These are supported configuration
  bounds, not a guarantee that every invocation completes within that time.
- PreToolUse, SessionEnd and Codex PermissionRequest must be synchronous. Other
  handlers may be synchronous or asynchronous.
- Its executable must be runnable and have the same bytes as the observing CLI
  build. A different path to identical bytes is acceptable. Refresh hooks after
  upgrading if they still point to an older build.

Global hook disabling must be off. Codex must enable a supported hooks feature,
and none of the installed Secuarden hook-state entries may be disabled.

Formatting, descriptions, unrelated hooks/settings, longer supported timeouts,
privacy preferences, cloud sync settings and unrelated project trust changes do
not alter compliance. Settings are inspected without invoking configured commands.
Raw settings, credentials, executable contents and source code are not stored.

The contract covers **shared user-level adapter hook configuration**. It does not
certify project/managed overrides, runtime trust approval, effective activation,
repository capture scope, storage health, or delivery. `verify-live` remains the
separate delivery check. Those exclusions are explicit limits, not passing checks.

## Observation and reporting

```sh
secuarden attestation status
secuarden attestation check --json
secuarden attestation history --json
secuarden attestation verify
secuarden attestation disable
secuarden attestation enable
```

`watch` is a foreground monitor independent of hooks. It polls every 15 seconds;
run it under your process supervisor for continuous observation. No OS background
service is installed automatically. Without a watcher, reporting commands and
explicit checks take point-in-time observations. The dashboard reads stored state;
an explicitly selected alternate evidence database does not inherit this machine's
attestation.

Current states are `satisfied`, `violated`, `unknown`, `disabled`, or
`not_configured`. Checks and enable commands return nonzero unless requirements
are satisfied, while retaining the evaluation. Enabling is not permission to
accept the current configuration. Missing required hooks fail; malformed or
uninspectable configuration yields unknown results.

Records identify the adapter, contract version and digest, plus requirement IDs,
pass/fail/unknown results, and reasons. Deviations and restorations remain in the
append-only hash chain in `~/.secuarden/attestation.db`. Restoration starts at its
observation time and never repairs earlier uncertainty. Gaps over 90 seconds and
backward clock changes are recorded on the next enabled observation.

Reports retain all historical transitions, including deviations after restoration.
The history is OS-user-wide and all-time; it does not assert that a particular
commit or session was affected. Unchanged checks remain stored but are omitted
from displayed transition history. The optional chain seal includes the contract
history and head hash. Ordinary session sync does not upload this history.

Disabling records a transition and stops configuration observations, without
changing the embedded contracts or deleting history. `verify` checks stored
checksums, not current compliance. A disabled or violated installation can have
an intact history. The existing risk gate displays attestation without imposing
an additional blocking policy.

## Upgrades and existing history

`attestation baseline` no longer accepts snapshots; it returns an explanatory
error, including for old invocations with `--reason`. Requirements change only
through an updated embedded contract, not a configuration file or CLI override.
Contract changes must increment the adapter contract version. The digest also
captures the definition, so a definition change is visible even if a version was
accidentally reused.

The next enabled check records `contract_changed` before evaluating a new
contract. Old records retain their original contract identity and results.

Existing snapshot-based history is not rewritten or rehashed. Until evaluated
against a contract, enabled legacy history reports `legacy_unverified`. The first
enabled check appends `contract_migrated` and the actual compliance result, retaining
all previous baselines, deviations and checksums. Disabled legacy installations
remain disabled until explicitly enabled.

## Limits and module boundaries

Polling can miss a disable-and-restore between observations. A machine owner can
stop the monitor, replace the CLI, or rewrite local records and recompute checksums.
The binary defines correctness within this local trust boundary; it is not an
independent enforcement authority. An accepted SaaS seal strengthens the integrity
claim for a submitted snapshot, not observations that never occurred.

- `internal/capturecontract`: embedded, versioned adapter requirements.
- `internal/agent/attestation.go`: observation and contract evaluation.
- `internal/attestation/model.go`: versioned contract identities and result records;
  legacy snapshot fields remain solely for checksum compatibility.
- `internal/attestation/engine.go`: enable/disable, contract adoption, deviation,
  restoration and gap transitions, using an injected observer.
- `internal/attestation/store.go`: SQLite transactions and checksum validation.
- `internal/attestation/report.go`: current/historical reporting semantics.
- `cmd/attestation.go`: commands and independent foreground monitoring.
