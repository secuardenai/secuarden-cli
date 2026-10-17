# Git ledger, Codex observations, and signed receipts

[Back to README](../README.md)

### Git change ledger

The ledger records an exact committed Git revision in `~/.secuarden/ledger.db`,
separate from the activity database. Choose an exact base or a target ref whose
merge base with the head defines the change. The ref must be available locally.

```bash
secuarden ledger build --repo . --head HEAD --base-ref origin/main
# Replace CHANGE_DIGEST with the digest returned by build
secuarden ledger show CHANGE_DIGEST
```

Uncommitted work is excluded. Building a change record does not by itself prove
which agent authored it.

### Codex observations (opt-in)

The independent observation inbox is separate from the main activity collector.
Enabling it does not install hooks or grant Codex trust. Use the installed binary:

```bash
secuarden ledger capture enable
secuarden ledger capture status

# Print the proposed hook fragment for review
secuarden ledger capture hooks

# Explicitly merge it into Codex hooks, preserving existing entries
secuarden ledger capture hooks --install "$HOME/.codex/hooks.json"

# After supported Codex sessions, normalize queued observations into the ledger
secuarden ledger process
```

The inbox defaults to `~/.secuarden/observations`. Codex must support and enable the
relevant hooks, and any required trust approval must be handled in Codex.
`capture trust` records an operator report; it does not grant trust.
`capture disable` stops inbox capture without deleting the stored observations.

Use `secuarden ledger checkpoint --repo . --session SESSION_ID --kind start` and the same
command with `--kind end` at the actual session boundaries. Checkpoints record
current Git state and cannot be backdated. To relate processed observations to a
stored change, provide a session and an explicit time window:

```bash
# Replace the digest, session ID, and timestamps with your recorded values
secuarden ledger correlate CHANGE_DIGEST --session SESSION_ID \
  --since 2026-10-10T09:00:00Z --until 2026-10-10T10:00:00Z
secuarden ledger coverage CHANGE_DIGEST --full
```

Coverage reports expose gaps and inferred links. A correlation is evidence of a
relationship, not proof that every changed line was authored by the agent.

### Signed change receipts

Receipts bind a committed Git change and its evidence snapshot using an Ed25519
signature. Creation requires a GitHub repository identity, repository-specific
SaaS credentials, and a compatible HTTPS server for signing-key registration.
It saves the signed artifact locally and attempts upload; this is not an offline
command. The current signing key is generated in process memory, not persisted
as a private-key file.

```bash
# Configure this repository for explicit receipt creation
secuarden init --repo . --api-key YOUR_API_KEY --receipt-mode explicit

# Create, save, and upload a receipt for the committed change
secuarden ledger receipt create --repo . --head HEAD --base-ref origin/main

# Replace RECEIPT_ID with the ID returned by create
secuarden ledger receipt show RECEIPT_ID
secuarden ledger receipt export RECEIPT_ID --output receipt.json
secuarden ledger receipt upload RECEIPT_ID
```

Export writes a new file and will not overwrite an existing one. If upload fails
after the artifact is saved, inspect its status and retry with `receipt upload`.
To include explicit session scopes during creation, pass `--session` together
with ordered RFC3339 `--since` and `--until` values. Process queued observations
before creating the receipt; its evidence snapshot is fixed at creation.

Automatic receipts are opt-in through
`secuarden init --repo . --receipt-mode automatic --receipt-base-ref origin/main`. This installs a Git pre-push hook. It preserves
an existing hook's rejection, but Secuarden receipt failures do not reject the
push. Pushing the target branch itself requires a destination-specific
`--receipt-branch-base refs/heads/BRANCH=REF`. A pre-push receipt records a push
attempt, not confirmation that the remote accepted it.
