# Live capture verification

[Back to README](../README.md)

`init` configures hooks and arms a 15-minute verification window for each configured agent. Installation succeeds with **verification pending**, including unattended installation. It never waits for interactive input for this verification step. To start again:

```sh
secuarden verify-live --repo /absolute/path/to/repo --agent codex --client vscode
```

Start a new conversation after arming, ask the agent to run `pwd`, then check its exact session ID:

```sh
secuarden verify-live --repo /absolute/path/to/repo --agent codex --client vscode --session EXACT_SESSION_ID --wait 60s
```

`--wait` defaults to zero and is capped at five minutes. Cancellation is supported. Repeating the check within the window allows asynchronous hooks to finish. Arming again replaces the pending window, not the last successful result. Incomplete verification prints its stage and returns normally, because pending runtime verification is not an installation failure; invalid arguments, expired/stale windows, and storage errors return errors. Scripts must inspect the reported stage, not interpret exit zero as capture success.

The selected session must have no events preceding the window. A persisted session-start event and pre/post events with the same invocation ID and tool, agent, session, and canonical repository establish a tool round-trip. Both current agent integrations support these phases. A post event means a result was received, not that the tool succeeded. Stop/session exit is unnecessary, including Codex's turn-boundary Stop. No command, prompt, or output text is required. Verification never invokes hooks, generates synthetic capture events, changes scope/privacy, or enables cloud sync.

Status reports the last verified time for the current repository. It also evaluates current capture scope: removing the repository from the allowlist explicitly reports that capture is currently excluded, while preserving the historical timestamp. Configuration or executable fingerprint changes and detectable runtime/CLI version changes mark it stale. Dependency validation reports **configured command missing** for deleted executables or broken symlinks, and **configured command not executable** for permission failures. It checks the filesystem and resolves bare commands using the diagnosing process’s PATH; the client may have a different PATH. It does not execute hooks or prove that the OS loader, script interpreter, or running client can launch them; live verification establishes delivery. Fingerprints include resolved executable paths and contents and conservatively hash the full relevant settings files, so unrelated edits within those files can also invalidate verification. No activity-age threshold marks an idle client unhealthy. Runtime checks inspect the installed runtime, not the version loaded in every running client process. Observed agent version is retained when supplied by hooks.

Verification metadata is stored in the existing local database metadata table: time, agent, session, repository, declared client, available versions, configuration fingerprint, and event IDs. No extra payload or prompt copies are retained. The existing hash-integrity command, repository baseline, and SaaS delivery remain independent.

## Exact manual acceptance procedure: VS Code Codex

Build from the checkout root at a persistent installation path, keeping the executable basename exactly `secuarden` so installed hooks are recognized:

```sh
export SECUARDEN_LIVE_DIR="$HOME/.local/bin"
mkdir -p "$SECUARDEN_LIVE_DIR"
go build -o "$SECUARDEN_LIVE_DIR/secuarden" ./cmd/secuarden
```

Keep the executable installed: hooks use its absolute path. This build replaces any existing secuarden binary at that path. In a separate terminal, set `SECUARDEN_LIVE_DIR` to the same directory (shown by `echo "$SECUARDEN_LIVE_DIR"`); do not create another directory.

1. Use that binary for all following commands. Configure hooks with `"$SECUARDEN_LIVE_DIR/secuarden" init --repo /absolute/path/to/repo --agent codex`. Preserve existing scope/privacy; if hooks are disabled, make an explicit decision about enabling them. Do not add API credentials for this test.
2. Save work and finish active tasks. Reload the intended VS Code window using **Developer: Reload Window**. Review hook approval prompts if presented. These are manual activation steps, not proof that stale configuration caused an earlier failure.
3. In a separate terminal run `"$SECUARDEN_LIVE_DIR/secuarden" verify-live --repo /absolute/path/to/repo --agent codex --client vscode`.
4. In that VS Code window start a **new** Codex conversation in the same repository. Ask: “Run `pwd` once, then stop. Do not modify files.” Allow its tool call to finish. Do not manually invoke `secuarden hook`.
5. Obtain the exact conversation/thread ID from the intended client's conversation information or the corresponding Codex local session record. If using a local record, establish its association with this conversation and repository; selecting the most recent database session is insufficient. If the association cannot be established, leave acceptance incomplete.
6. Run `"$SECUARDEN_LIVE_DIR/secuarden" verify-live --repo /absolute/path/to/repo --agent codex --client vscode --session EXACT_SESSION_ID --wait 60s`.
7. Expect persisted request and corresponding result evidence, with a last-verified timestamp. Run `"$SECUARDEN_LIVE_DIR/secuarden" status` from the repository and confirm the same timestamp. The command must still say **client surface unknown / VS Code not independently verified**. Human observation of steps 4–5 supplies the VS Code association for manual acceptance; the current hook payload cannot prove it automatically.
8. Negative checks: arm again and check the old session ID (must reject it); arm and start a new conversation without performing a tool action (must not report a tool round-trip). An unrelated desktop session must not satisfy a check pinned to the intended VS Code session ID. Changing hook settings must mark the previous result stale. Do not change production hook settings solely to exercise this last case; automated isolated fixtures cover it.

## Recorded manual validation — 17 October 2026

On macOS ARM64, source commit `73f5170` was tested with the Codex VS Code
extension `26.1007.21434`. A fresh conversation in the selected disposable Git
repository ran `pwd`. Verification of that exact session reported a persisted
tool request and corresponding result at **2026-10-17T04:54:20Z**; `status`
reported the same last-verified timestamp. The operator's VS Code test and local
session metadata established the manual client association. The verifier
continued to report the client surface as unknown.

After the original hook configuration was restored, status correctly marked the
historical result stale. This was a focused round-trip check, not completion of
every acceptance or negative check above. It did not validate other platforms,
full checkpoint completeness, hash integrity, receipt upload, observation-inbox
processing, or SaaS delivery. Automated fixtures remain separate from live
acceptance evidence.

## Incomplete results

- `no_matching_event`: no matching persisted evidence; activation and trust remain unverified.
- `fresh_session_start_missing` / `session_not_fresh`: start a fresh conversation after arming.
- `request_received_result_missing`: request persisted, but its corresponding result has not.
- `events_received_round_trip_pending`: other matching events arrived; no tool pair yet.
- `capture_persistence_failure`: storage recorded capture failure for the selected session.
- Scope exclusion or missing/disabled configuration is reported before waiting.

A failure before the database opens cannot be reliably attributed from database evidence. Inspect `~/.secuarden/error.log` locally; do not share raw logs without reviewing their contents. Scope skips are aggregate counters, so the verifier reports the intended repository's current scope decision instead of attributing unrelated skip counts to the test. Where configuration may not have loaded, save work, finish tasks, reload/restart the relevant client, start a new conversation, review approvals if presented, and repeat. No client is restarted or trusted automatically, and no universal `/hooks` command is assumed.
