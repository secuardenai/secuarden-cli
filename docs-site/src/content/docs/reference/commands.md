---
title: "CLI command reference"
description: "An initial command map; the installed binary provides authoritative flags."
banner:
  content: "Development preview — starter documentation, not yet release-validated."
---

Use `secuarden --help` and `secuarden COMMAND --help` for the version you installed.
This page is a navigation scaffold, not yet a generated flag-by-flag reference.

| Command | Purpose |
| --- | --- |
| `init --repo PATH` | Configure a repository and supported agent integration. |
| `status` | Inspect capture health and recorded activity. |
| `events` | Browse captured event records. |
| `session ID` | Investigate a captured session. |
| `report` | Summarize evidence for a repository and time window. |
| `chain` | Connect captured prompts and edits to a commit range. |
| `serve` | Open a local evidence dashboard. |
| `verify-live` | Check a real runtime capture round-trip. |
| `verify` | Verify stored activity checksums. |
| `bom` | Export an AI bill of materials. |
| `gate` | Evaluate captured evidence against risk rules. |
| `hooks refresh` | Refresh installed hook commands. |
| `attestation` | Inspect contracts and configuration history. |

## Configuration attestation

```sh
secuarden attestation contracts
secuarden attestation enable --help
secuarden attestation check --json
secuarden attestation watch --help
```

`attestation check` returns nonzero unless the contract is satisfied. This includes
unconfigured, disabled and unknown states. See [troubleshooting](/troubleshooting/).
