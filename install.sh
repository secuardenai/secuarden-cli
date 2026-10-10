#!/bin/sh
# Secuarden install script
# Usage: curl -fsSL https://install.secuarden.ai | sh

set -e

REPO="secuardenai/secuarden-cli"
INSTALL_DIR="/usr/local/bin"
BINARY="secuarden"

# Detect OS and arch
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    OS="darwin"
    ;;
  Linux)
    OS="linux"
    ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)
    ARCH="amd64"
    ;;
  arm64 | aarch64)
    ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

# Only request platform archives included in the release configuration.
if [ "$OS/$ARCH" = "linux/arm64" ]; then
  echo "Unsupported platform: linux/arm64 (no release binary is published)" >&2
  exit 1
fi

# macOS ships shasum; Linux commonly provides sha256sum.
if command -v sha256sum >/dev/null 2>&1; then
  CHECKSUM_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  CHECKSUM_TOOL="shasum"
else
  echo "Checksum verification requires sha256sum or shasum" >&2
  exit 1
fi

# Get the latest release version
VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' \
  | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$VERSION" ]; then
  echo "Failed to determine latest version" >&2
  exit 1
fi

ARCHIVE="secuarden_${VERSION#v}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

echo "Installing secuarden ${VERSION} for ${OS}/${ARCH}..."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$URL" -o "$TMP/$ARCHIVE"
curl -fsSL "https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt" \
  -o "$TMP/checksums.txt"

# Select exactly one checksum for this archive; never verify unrelated entries.
EXPECTED=$(awk -v archive="$ARCHIVE" '$2 == archive { print $1 }' "$TMP/checksums.txt")
case "$EXPECTED" in
  "" | *[!0-9a-fA-F]*)
    echo "Missing, duplicate, or invalid checksum for $ARCHIVE" >&2
    exit 1
    ;;
esac
if [ "${#EXPECTED}" -ne 64 ]; then
  echo "Invalid checksum length for $ARCHIVE" >&2
  exit 1
fi

if [ "$CHECKSUM_TOOL" = "sha256sum" ]; then
  ACTUAL=$(sha256sum "$TMP/$ARCHIVE")
else
  ACTUAL=$(shasum -a 256 "$TMP/$ARCHIVE")
fi
ACTUAL=${ACTUAL%% *}
EXPECTED=$(printf '%s' "$EXPECTED" | tr 'A-F' 'a-f')
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "Checksum verification failed for $ARCHIVE; nothing installed" >&2
  exit 1
fi

tar -xzf "$TMP/$ARCHIVE" -C "$TMP"

install -m 755 "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
echo "Installed secuarden to $INSTALL_DIR/$BINARY"
echo "Run from your Git repository: secuarden init --repo ."
