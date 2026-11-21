---
title: "Verify and export"
description: "Distinguish recorded integrity from delivery and configuration."
banner:
  content: "Development preview — starter documentation, not yet release-validated."
---

## Verify stored activity

```sh
secuarden verify
secuarden verify --all
```

Stored-chain verification checks recorded evidence. It cannot establish that every
agent action was captured.

## Verify configuration history

```sh
secuarden attestation verify
```

An intact configuration history can include violations or periods with checks
disabled. History integrity and current compliance are separate results.

## Export

```sh
secuarden report --json
secuarden bom --since 30d
```

Treat exported evidence as sensitive. Review [configuration and privacy](/secuarden-cli/reference/configuration/)
before sharing it. Use [the command reference](/secuarden-cli/reference/commands/) for flags and scope.
