---
title: "Install Secuarden"
description: "Install a released CLI or build this development checkout."
banner:
  content: "v0.8.1 release candidate — publication pending."
---

## Install a release

```sh
curl -fsSL https://install.secuarden.ai | sh
secuarden version
secuarden --help
```

The installer currently selects published v0.8.0, which lacks `attestation` and
`chain`. These guides target the v0.8.1 candidate; see [version compatibility](/releases/).
Supported release binaries are macOS ARM64/AMD64 and Linux AMD64. Linux ARM64
and Windows binaries are not published. Installation requires write access to
`/usr/local/bin`; archive checksums are verified before replacement.

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

Open a local Git repository and choose the [Claude Code](/agents/claude-code/) or
[Codex](/agents/codex/) setup guide. Installation alone does not produce activity evidence.
