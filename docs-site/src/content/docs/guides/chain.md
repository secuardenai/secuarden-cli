---
title: "Prompt-to-merge chain"
description: "Inspect the relationship between captured edits and commits."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## Select a commit range

```sh
secuarden chain --repo . --base-ref origin/main
secuarden chain --repo . --base-ref origin/main --json
```

The reference must exist locally. Choose an appropriate base for the change you
want to inspect; a range whose base equals its head has no intervening commits.

## Interpret the record

This command is experimental. It associates a captured edit with the newest
commit in the selected range that touches the same path. It does not match the
edit's contents or timestamp to the commit, prove authorship, or establish that
the edit survived into the head revision. Older or uncommitted observations can
appear; a filename association is not proof the commit contains that edit.

Missing observations remain missing. The report's `checksum` label is not a
verification of its edit revisions or findings. Those records are outside the
stored event hashes checked by `secuarden verify`. A machine owner can rewrite
local records; review Git changes and capture qualifications separately.

## Optional SaaS seal

Select the range explicitly when sealing:

```sh
secuarden chain --repo . --base-ref origin/main --head HEAD --seal
```

This uploads evidence and requires a configured repository API key and a
compatible SaaS service. It is not an offline check. The client treats HTTP
200/201 as acceptance; these docs do not establish server retention or independent
verification guarantees. A signature does not strengthen the filename association
or recover uncaptured activity. Review the evidence and upload scope first.

See [configuration and privacy](/reference/configuration/) and
[verification](/integrity/verification/).
