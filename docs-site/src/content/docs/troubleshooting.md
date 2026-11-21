---
title: "Capture and setup troubleshooting"
description: "Resolve common setup states before interpreting evidence."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## Attestation reports `not_configured`

The CLI contains the contracts, but monitoring has not been initialized for this
OS user. Run:

```sh
secuarden attestation enable
```

Then use `secuarden attestation watch` for periodic observation.

## No captured events

Check that you initialized the correct repository, started a fresh agent session,
and completed runtime trust requirements. Run `secuarden status`, then inspect
`secuarden verify-live --help` for the delivery verification workflow.

## Collector build differs

After installing an upgraded binary:

```sh
secuarden hooks refresh
secuarden attestation check
```

Use the stable installed binary. Do not accept the changed configuration as a new
baseline; repair the integration so it satisfies the embedded contract.

## Configuration restored, but an old deviation remains

This is expected. Restoration appends a new event and retains the earlier period
of uncertainty. See [configuration monitoring](/integrity/monitoring/).
