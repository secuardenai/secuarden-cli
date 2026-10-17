#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: replay-fixtures.sh <secuarden-binary> <fixture-directory>" >&2
  exit 2
fi

binary=$1
fixtures=$2

echo "Fixture replay: sanitized Claude Code hook payloads"
echo "No live agent session and no SaaS sync"

"$binary" hook session-start < "$fixtures/01-session-start.json"
"$binary" hook pre-tool-use < "$fixtures/02-read.json"
"$binary" hook post-tool-use < "$fixtures/02-read-post.json"
"$binary" hook pre-tool-use < "$fixtures/03-sensitive-read.json"
"$binary" hook post-tool-use < "$fixtures/03-sensitive-read-post.json"
"$binary" hook pre-tool-use < "$fixtures/04-edit.json"
"$binary" hook post-tool-use < "$fixtures/04-edit-post.json"
"$binary" hook pre-tool-use < "$fixtures/05-command-pre.json"
"$binary" hook post-tool-use < "$fixtures/06-command-post.json"
"$binary" hook pre-tool-use < "$fixtures/07-mcp.json"
"$binary" hook post-tool-use < "$fixtures/07-mcp-post.json"
"$binary" hook session-end < "$fixtures/08-session-end.json"

echo "✓ Replayed 12 fixtures through the actual secuarden hook commands"
