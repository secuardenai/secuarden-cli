---
title: "CLI command reference"
description: "Command map for the v0.8.1 candidate."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

Use `secuarden --help` and `secuarden COMMAND --help` for the version you installed.
This is a command overview, not an exhaustive flag reference. See
[version compatibility](/releases/) before using `attestation` or `chain`.

| Command | Purpose |
| --- | --- |
| `init --repo PATH` | Configure a repository and supported agent integration. |
| `status` | Inspect capture health and recorded activity. |
| `events` | Browse captured event records. |
| `session ID` | Investigate a captured session. |
| `report` | Summarize evidence for a repository and time window. |
| `chain` | Experimentally associate captured edits with commits by path. |
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
