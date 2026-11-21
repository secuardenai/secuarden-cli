---
title: "Embedded capture contracts"
description: "Understand the minimum hook configuration defined by Secuarden."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## The contract lives in the binary

Each supported adapter has a versioned minimum capture contract. The installer
and checker use the same definition. The installed machine configuration cannot
redefine what counts as compliant.

```sh
secuarden attestation contracts
secuarden attestation check --json
```

## What is checked

- Required events invoke the correct Secuarden handlers.
- Hooks are enabled and match the required events.
- Execution settings preserve required ordering and supported timeout bounds.
- Configured collectors match the observing CLI build.
- Required Codex hook features and individual handlers are enabled.

Harmless formatting, descriptions and longer supported timeouts do not create
violations. A missing hook cannot be accepted by taking a new baseline.

## Separate checks, separate claims

Contract satisfaction concerns shared user-level hook configuration. It does not
certify runtime trust, project overrides, capture delivery or storage health.

Continue with [monitoring](/integrity/monitoring/) to retain configuration history.
