package cmd

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDemoReplayPreservesGitIdentity(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "secuarden")
	build := exec.Command("go", "build", "-o", binary, "./cmd/secuarden")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	repo, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Capture an alias, as happens with /var versus /private/var on macOS.
	capturedRepo := filepath.Join(t.TempDir(), "repository-alias")
	if err := os.Symlink(repo, capturedRepo); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = repo
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git: %v %s", err, out)
		}
	}
	git("init", "-b", "main")
	git("config", "user.name", "Demo")
	git("config", "user.email", "demo@example.invalid")
	git("commit", "--allow-empty", "-m", "baseline")
	const remote = "https://example.invalid/acme/demo-repository.git"
	git("remote", "add", "origin", remote)
	run := func(input []byte, success bool, args ...string) string {
		t.Helper()
		c := exec.Command(binary, args...)
		c.Dir = repo
		c.Stdin = bytes.NewReader(input)
		out, err := c.CombinedOutput()
		if (err == nil) != success {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	// Operational errors are concise; parser/argument errors retain usage.
	for _, args := range [][]string{
		{"init", "--repo", repo, "--agent", "claude-code"},
		{"verify-live", "--repo", repo, "--agent", "claude-code"},
		{"sync", "--session", "missing"},
		{"serve", "--database", repo},
	} {
		out := run(nil, false, args...)
		if strings.Contains(out, "Usage:") {
			t.Fatalf("operational usage: %s", out)
		}
		if args[0] == "init" && (!strings.Contains(out, "Claude Code was not detected") || strings.Contains(out, "use --agent claude-code")) {
			t.Fatal(out)
		}
	}
	for _, name := range []string{"init", "gate", "sync", "serve", "verify-live"} {
		for _, arg := range []string{"--not-a-flag", "unexpected-argument"} {
			out := run(nil, false, name, arg)
			if !strings.Contains(out, "Usage:") {
				t.Fatalf("missing syntax usage: %s", out)
			}
		}
	}
	fixtures := []struct{ file, hook string }{
		{"01-session-start.json", "session-start"}, {"02-read.json", "pre-tool-use"}, {"02-read-post.json", "post-tool-use"},
		{"03-sensitive-read.json", "pre-tool-use"}, {"03-sensitive-read-post.json", "post-tool-use"},
		{"04-edit.json", "pre-tool-use"}, {"04-edit-post.json", "post-tool-use"},
		{"05-command-pre.json", "pre-tool-use"}, {"06-command-post.json", "post-tool-use"},
		{"07-mcp.json", "pre-tool-use"}, {"07-mcp-post.json", "post-tool-use"}, {"08-session-end.json", "session-end"},
	}
	var session string
	for i, f := range fixtures {
		raw, err := os.ReadFile(filepath.Join("..", "docs", "demo", "fixtures", f.file))
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		session = payload["session_id"].(string)
		if i == 0 {
			payload["cwd"] = capturedRepo
		} else if _, ok := payload["cwd"]; ok {
			t.Fatalf("fixture %s unexpectedly has cwd", f.file)
		}
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		run(raw, true, "hook", f.hook)
	}
	db, err := sql.Open("sqlite", filepath.Join(os.Getenv("HOME"), ".secuarden", "secuarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var branch, url, completeness string
	if err := db.QueryRow("SELECT git_branch, git_repo_url, completeness_state FROM sessions WHERE id=?", session).Scan(&branch, &url, &completeness); err != nil {
		t.Fatal(err)
	}
	if branch != "main" || url != remote || completeness != "partial" {
		t.Fatalf("session: %q %q %q", branch, url, completeness)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE session_id=? AND git_branch='main' AND git_repo_url=?", session, remote).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 12 {
		t.Fatalf("only %d events retained identity", count)
	}
	t.Logf("session git_branch=%s git_repo_url=%s; all %d events match; checkpoints remain %s", branch, url, count, completeness)
	report := run(nil, true, "report", "--repo", repo)
	if !strings.Contains(report, "1 repository file changed · 0 external files changed") {
		t.Fatal(report)
	}
	t.Log("report: 1 repository file changed; 0 external files changed")
	run(nil, true, "verify", "--all")
	t.Log("verify: exit 0")
	// Verify-live succeeds only once the fresh session's matching pair persists.
	settings := filepath.Join(os.Getenv("HOME"), ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	run(nil, true, "init", "--repo", repo, "--agent", "claude-code", "--receipt-mode", "explicit")
	run(nil, false, "verify-live", "--repo", repo, "--agent", "claude-code")
	for i, fixture := range fixtures[:3] {
		raw, err := os.ReadFile(filepath.Join("..", "docs", "demo", "fixtures", fixture.file))
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		payload["session_id"] = "live-round-trip"
		payload["cwd"] = repo
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		run(raw, true, "hook", fixture.hook)
		run(nil, i == 2, "verify-live", "--repo", repo, "--agent", "claude-code", "--session", "live-round-trip")
	}
	t.Log("verify-live: pending exits nonzero; persisted matching request/result exits 0")
	// Explicit cwd must refresh identity, while the earlier events remain historical.
	git("checkout", "-b", "feature")
	git("remote", "set-url", "origin", "https://example.invalid/acme/other.git")
	missingCWD, _ := json.Marshal(map[string]string{"session_id": session})
	run(missingCWD, true, "hook", "session-start")
	if err := db.QueryRow("SELECT git_branch, git_repo_url FROM events WHERE session_id=? ORDER BY sequence DESC LIMIT 1", session).Scan(&branch, &url); err != nil {
		t.Fatal(err)
	}
	if branch != "main" || url != remote {
		t.Fatalf("missing cwd rescanned Git: %s %s", branch, url)
	}
	payload, _ := json.Marshal(map[string]string{"session_id": session, "cwd": repo})
	run(payload, true, "hook", "session-start")
	if err := db.QueryRow("SELECT git_branch, git_repo_url FROM events WHERE session_id=? ORDER BY sequence DESC LIMIT 1", session).Scan(&branch, &url); err != nil {
		t.Fatal(err)
	}
	if branch != "feature" || url != "https://example.invalid/acme/other.git" {
		t.Fatalf("cwd did not refresh: %s %s", branch, url)
	}
	run(nil, true, "verify", "--all")
	if _, err := db.Exec("UPDATE events SET event_hash='flipped' WHERE session_id=? AND sequence=1", session); err != nil {
		t.Fatal(err)
	}
	run(nil, false, "verify", "--all")
	out := run(nil, false, "gate")
	if strings.Contains(out, "Usage:") {
		t.Fatal(out)
	}
	t.Log("flipped event hash: verify exits nonzero; gate fails without usage")
}
