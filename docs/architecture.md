# Architecture and evidence contracts

[Back to README](../README.md)

## Main activity capture

Claude Code or Codex delivers supported hook events to the installed Secuarden
binary. Secuarden parses the payload, applies sensitive-path detection and
redaction, adds identity and repository context, and stores the event locally.
Hook coverage and timing depend on the agent and event.

```text
Agent hooks → Secuarden parser and redaction → ~/.secuarden/secuarden.db
                                                   │
                                       status / events / report / verify
                                                   │
                                      optional repository SaaS sync
```

Versioned event hashes link records within each session. Session hashes cover
repository, branch, model, and developer identity. Verification checks stored
evidence integrity; it cannot prove that every agent action was captured or that
an inferred relationship establishes authorship.

## Separate evidence workflows

The Git ledger records committed revisions in `~/.secuarden/ledger.db`. Independent
Codex observations first enter `~/.secuarden/observations` and are normalized by
`secuarden ledger process`. Correlation associates observations with an explicit
change and session window while retaining gaps and confidence information.

Signed receipts bind a Git change and its evidence snapshot. They use a separate
registration and upload protocol; see the [ledger guide](ledger.md) for network
requirements, signing-key handling, and pre-push behavior.

## Contracts

- [Stage 1 evidence contract](contracts/stage1-evidence-contract.md)
- [Capture, ingestion, and presentation](contracts/capture-ingestion-presentation.md)
- [Session upload envelope](contracts/session-upload-envelope.md)
- [Stage 1 event schema](../schema/stage1/v2/event.schema.json)
- [Session schema](../schema/stage1/v2/session.schema.json)
- [Upload schema](../schema/upload/v1/session-envelope.schema.json)

