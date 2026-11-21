---
title: "Configuration and privacy"
description: "Understand local data and optional cloud operations."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## Local by default

Local evidence collection does not require a SaaS account. Optional repository
sync and explicit SaaS seals are separate features.

| Location | Purpose |
| --- | --- |
| `~/.secuarden/config.json` | Repository integrations and capture settings. |
| `~/.secuarden/secuarden.db` | Captured activity. |
| `~/.secuarden/attestation.db` | Configuration-contract observation history. |
| `~/.secuarden/ledger.db` | Git ledger and receipt records. |

Keep API keys outside the worktree. Omitting an API key during later setup does
not necessarily disable an already configured integration.

## Capture scope and setup

New installations default to all supported sessions for this OS user. Use
`secuarden init --repo . --scope repo` to select repository-only capture;
this is a shared OS-user setting, not a per-shell override. Setup preserves an
existing scope unless explicitly changed. New setups enable configuration
attestation by default; an existing explicit disable is preserved.

## Evidence can be sensitive

Filtering and redaction reduce exposure; they do not guarantee removal of every
secret. Paths and metadata can also be sensitive. Review exports before sharing.

## Configuration contracts

Contracts are embedded in the CLI, not supplied through an editable policy file.
Their current scope is shared adapter hook configuration. See
[embedded capture contracts](/integrity/contracts/).
