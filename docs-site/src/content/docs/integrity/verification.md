---
title: "Verify and export"
description: "Distinguish recorded integrity from delivery and configuration."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## Verify stored activity

```sh
secuarden verify
secuarden verify --all
```

Stored-chain verification checks recorded evidence. It cannot establish that every
agent action was captured. It verifies stored event chains and session metadata,
not the separate experimental edit-revision and posture-finding tables or a
Git commit association. Partial capture can coexist with valid hashes.

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

Treat exported evidence as sensitive. Review [configuration and privacy](/reference/configuration/)
before sharing it. Use [the command reference](/reference/commands/) for flags and scope.
