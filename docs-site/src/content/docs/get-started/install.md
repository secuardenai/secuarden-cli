---
title: "Install Secuarden"
description: "Install a released CLI or build this development checkout."
banner:
  content: "Development preview — starter documentation, not yet release-validated."
---

## Install a release

```sh
curl -fsSL https://install.secuarden.ai | sh
secuarden version
secuarden --help
```

The installer selects a published release. Commands described in this development
preview may not yet be present in that release.

## Build this checkout

From the repository root, with the Go version required by `go.mod`:

```sh
make build
./bin/secuarden --help
```

Use a stable installed binary when configuring hooks. They retain its executable
path; do not use `go run` to install hooks. `make install` copies the binary to
`/usr/local/bin` and requires write permission there.

## Next step

Open a local Git repository and choose the [Claude Code](/secuarden-cli/agents/claude-code/) or
[Codex](/secuarden-cli/agents/codex/) setup guide. Installation alone does not produce activity evidence.
