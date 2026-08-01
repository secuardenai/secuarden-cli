#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/../.." && pwd)
work_root=/private/tmp/secuarden-terminal-demo
demo_home=$work_root/home
demo_repo=$work_root/repository
frames=$work_root/frames
binary=$work_root/bin/secuarden
transcript=$work_root/transcript.txt
output=$script_dir/secuarden-terminal-demo.gif
go_module_cache=$(go env GOMODCACHE)
host_home=$HOME

cleanup() {
  rm -rf "$work_root"
  rm -f "$script_dir"/.secuarden-terminal-demo.gif-*
}
trap cleanup EXIT

rm -rf "$work_root"
rm -f "$script_dir"/.secuarden-terminal-demo.gif-*
mkdir -p "$demo_home/.claude" "$demo_repo/src/auth" "$frames" "$(dirname "$binary")"
printf '{}\n' > "$demo_home/.claude/settings.json"
printf 'export const middleware = true\n' > "$demo_repo/src/auth/middleware.ts"
printf 'DEMO_VALUE=placeholder\n' > "$demo_repo/.env.example"

export HOME=$demo_home
export USER=demo
export LOGNAME=demo
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=$demo_home/.gitconfig
export GOMODCACHE=$go_module_cache
export GOCACHE=$work_root/go-build-cache
export PATH="$(dirname "$binary"):$PATH"

git -C "$demo_repo" init -q
git -C "$demo_repo" symbolic-ref HEAD refs/heads/main
git -C "$demo_repo" config user.name "Demo Developer"
git -C "$demo_repo" config user.email "developer@example.invalid"
git -C "$demo_repo" remote add origin https://example.invalid/acme/demo-repository.git

CGO_ENABLED=0 go build \
  -ldflags "-X github.com/secuardenai/secuarden-cli/cmd.Version=v0.2.0" \
  -o "$binary" "$repo_root/cmd/secuarden"

cd "$demo_repo"
"$binary" init >/dev/null
replay_output=$(
  "$script_dir/replay-fixtures.sh" "$binary" "$script_dir/fixtures"
)

status_output=$("$binary" status)
events_output=$("$binary" events --last 10)
report_output=$("$binary" report --since 24h --limit 4)

printf '%s\n' \
  'Secuarden CLI — local accountability demo' \
  '' \
  '$ ./docs/demo/replay-fixtures.sh' \
  "$replay_output" \
  '' \
  'All activity is synthetic and remains in isolated local SQLite.' \
  > "$frames/01-replay.txt"

printf '%s\n' \
  '$ secuarden events --last 10' \
  "$events_output" \
  > "$frames/02-events.txt"

printf '%s\n' \
  '$ secuarden report --since 24h --limit 4' \
  "$report_output" \
  > "$frames/03-report.txt"

printf '%s\n' \
  '$ secuarden status' \
  "$status_output" \
  > "$frames/04-status.txt"

{
  for frame in "$frames"/*.txt; do
    printf '%s\n' "$(basename "$frame")"
    sed -n '1,200p' "$frame"
  done
} > "$transcript"

for forbidden in \
  "$(id -un)" \
  "$(hostname)" \
  "$host_home" \
  "$(git -C "$repo_root" config user.name 2>/dev/null || true)" \
  "$(git -C "$repo_root" config user.email 2>/dev/null || true)" \
  "$(git -C "$repo_root" remote get-url origin 2>/dev/null || true)" \
  "$repo_root"; do
  if [[ -n "$forbidden" ]] && grep -Fq "$forbidden" "$transcript" "$script_dir"/fixtures/*.json; then
    echo "privacy audit failed: generated transcript contains host information" >&2
    exit 1
  fi
done

if grep -Eiq '(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|password[[:space:]]*=|authorization:[[:space:]]*bearer)' "$transcript" "$script_dir"/fixtures/*.json; then
  echo "privacy audit failed: credential-like text detected" >&2
  exit 1
fi

swift "$script_dir/render.swift" "$frames" "$output"

size=$(stat -f%z "$output" 2>/dev/null || stat -c%s "$output")
if (( size >= 5000000 )); then
  echo "GIF is too large: $size bytes" >&2
  exit 1
fi

echo "Generated docs/demo/secuarden-terminal-demo.gif ($size bytes)"
echo "Privacy audit passed: fixture replay is sanitized and isolated."
