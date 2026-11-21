---
title: "Reports and dashboard"
description: "Inspect recorded activity without leaving the machine."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## Summarize activity

```sh
secuarden report --since 24h
secuarden report --since 24h --md
secuarden report --since 24h --json
```

Reports default to the current Git repository. Use `--repo` to select another
repository or `--all-repos` for a cross-repository view.

## Investigate a session

```sh
secuarden events --last 20
secuarden session SESSION_ID
```

Replace `SESSION_ID` with an identifier from your captured evidence.

## Open the dashboard

```sh
secuarden serve
```

Open `http://127.0.0.1:8743`. The dashboard is a local, read-only evidence browser.

## Read capture qualifications

Configuration attestation includes current contract results and historical
deviations. Its history is OS-user-wide; it does not prove a particular commit
was affected. See [configuration monitoring](/integrity/monitoring/).
