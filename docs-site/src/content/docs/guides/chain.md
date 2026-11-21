---
title: "Prompt-to-merge chain"
description: "Inspect the relationship between captured edits and commits."
banner:
  content: "Development preview — starter documentation, not yet release-validated."
---

## Select a commit range

```sh
secuarden chain --repo . --base-ref origin/main
secuarden chain --repo . --base-ref origin/main --json
```

The reference must exist locally. Choose an appropriate base for the change you
want to inspect; a range whose base equals its head has no intervening commits.

## Interpret the record

The report connects captured prompts, edits, findings, and committed changes where
available. Missing observations remain missing. Local checksums do not prevent a
machine owner from rewriting records and recomputing them.

## Optional SaaS seal

`secuarden chain --seal` requires a configured repository API key and server
acceptance. It is not an offline operation. Review configuration and the upload
contract before enabling cloud features.

See [configuration and privacy](/secuarden-cli/reference/configuration/) and
[verification](/secuarden-cli/integrity/verification/).
