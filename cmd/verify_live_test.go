package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/agent"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/live"
	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

func TestLiveCommandPendingTimeoutScopeAndStale(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fakeBin := t.TempDir()
	if err := os.WriteFile(filepath.Join(fakeBin, "secuarden"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", dir).CombinedOutput(); err != nil {
		t.Fatalf("%s %v", out, err)
	}
	r, err := repository.ResolveCurrent(dir)
	if err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(os.Getenv("HOME"), ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0700); err != nil {
		t.Fatal(err)
	}
	raw := `{"hooks":{"SessionStart":[{"hooks":[{"command":"secuarden hook session-start"}]}],"PreToolUse":[{"hooks":[{"command":"secuarden hook pre-tool-use"}]}],"PostToolUse":[{"hooks":[{"command":"secuarden hook post-tool-use"}]}]}}`
	if err := os.WriteFile(settings, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	c := &cobra.Command{}
	c.SetContext(context.Background())
	c.SetOut(&out)
	run := func(session string, wait time.Duration) error {
		out.Reset()
		return runLive(c, dir, "claude-code", "vscode", session, wait)
	}
	before := time.Now()
	if err := run("", 0); err != nil {
		t.Fatal(err)
	}
	if time.Since(before) > time.Second || !strings.Contains(out.String(), "verification pending") {
		t.Fatal(out.String())
	}
	if err := run("fresh", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no_matching_event") {
		t.Fatal(out.String())
	}
	if err := run("fresh", 6*time.Minute); err == nil {
		t.Fatal("unbounded wait")
	}
	path, _ := storage.DefaultDBPath()
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := live.Key("claude-code", r.Root)
	var state live.State
	if _, err := db.ReadLiveState(key+"_pending", &state); err != nil {
		t.Fatal(err)
	}
	state.Started = time.Now().Add(-16 * time.Minute)
	if err := db.WriteLiveState(key+"_pending", state); err != nil {
		t.Fatal(err)
	}
	if err := run("fresh", 0); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatal(err)
	}
	if err := run("", 0); err != nil {
		t.Fatal(err)
	}
	fp, _ := agent.HookFingerprint("claude-code")
	if err := os.WriteFile(settings, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, _ := agent.HookFingerprint("claude-code")
	if fp == changed {
		t.Fatal("fingerprint unchanged")
	}
	if err := run("fresh", 0); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatal(err)
	}
	now := time.Now()
	state.VerifiedAt = &now
	state.Fingerprint = fp
	state.CLIVersion = Version
	if err := db.WriteLiveState(key, state); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastLiveLabel(db, "claude-code", r.Root), "STALE") {
		t.Fatal("status missed stale config")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.CaptureScope = config.CaptureScopeApproved
	cfg.ApprovedRepositories = nil
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := run("", 0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "excluded by capture scope") {
		t.Fatal(out.String())
	}
}

// This tests installation/arming with a built executable and synthetic Codex
// capability responses, not live agent acceptance. Execute the documented build
// command itself so a future basename regression in the procedure is caught.
func TestDocumentedLiveBuildInstallsRecognizedHooksAndArms(t *testing.T) {
	document, err := os.ReadFile("../docs/live-capture-verification.md")
	if err != nil {
		t.Fatal(err)
	}
	var buildLine string
	for _, line := range strings.Split(string(document), "\n") {
		if strings.HasPrefix(line, "go build -o ") {
			buildLine = line
			break
		}
	}
	if buildLine == "" {
		t.Fatal("acceptance procedure has no build command")
	}
	buildDir := t.TempDir()
	build := exec.Command("/bin/sh", "-c", buildLine)
	build.Dir = ".."
	build.Env = append(os.Environ(), "SECUARDEN_LIVE_DIR="+buildDir)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("documented build: %v\n%s", err, output)
	}
	binary := filepath.Join(buildDir, "secuarden")
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("documented build must produce a binary named secuarden: %v", err)
	}

	t.Setenv("HOME", t.TempDir())
	// Isolate capability inspection from installed clients and user configuration.
	fakeBin := t.TempDir()
	fakeCodex := `#!/bin/sh
case "$1" in
 --version) echo 'codex-cli test-version' ;;
 --help) echo 'features hooks hook-trust' ;;
 features) echo 'hooks experimental true' ;;
 *) exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(fakeBin, "codex"), []byte(fakeCodex), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	codexDir := filepath.Join(os.Getenv("HOME"), ".codex")
	if err := os.MkdirAll(codexDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte("[features]\nhooks = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if output, err := exec.Command("git", "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, output)
	}
	run := func(args ...string) string {
		t.Helper()
		command := exec.Command(binary, args...)
		command.Dir = repo
		command.Stdin = strings.NewReader("")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, output)
		}
		return string(output)
	}
	run("init", "--repo", repo, "--agent", "codex")
	if !agent.LiveHooksConfigured("codex") {
		t.Fatal("hooks installed by documented binary are not recognized")
	}
	hooks, err := os.ReadFile(filepath.Join(codexDir, "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	canonicalBinary, err := filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hooks), binary) && !strings.Contains(string(hooks), canonicalBinary) {
		t.Fatal("hooks do not reference documented binary")
	}
	output := run("verify-live", "--repo", repo, "--agent", "codex", "--client", "vscode")
	if !strings.Contains(output, "Hooks configured; live verification pending (15-minute window)") {
		t.Fatalf("verification did not arm:\n%s", output)
	}
	root, err := repository.ResolveCurrent(repo)
	if err != nil {
		t.Fatal(err)
	}
	path, err := storage.DefaultDBPath()
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var state live.State
	found, err := db.ReadLiveState(live.Key("codex", root.Root)+"_pending", &state)
	if err != nil || !found || state.Stage != "pending" || state.RequestedClient != "vscode" || state.Fingerprint == "" {
		t.Fatalf("missing armed state: %+v, found=%v, err=%v", state, found, err)
	}
}

// Diagnostics must preserve the historical timestamp while explicitly marking
// a broken dependency, even when no configuration bytes have changed.
func TestLastLiveMissingExecutable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	bin := filepath.Join(t.TempDir(), "secuarden")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(os.Getenv("HOME"), ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	hooks := map[string]interface{}{}
	for _, event := range []string{"SessionStart", "PreToolUse", "PostToolUse"} {
		hooks[event] = []interface{}{map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"command": bin, "args": []string{"hook", "test"}}}}}
	}
	raw, err := json.Marshal(map[string]interface{}{"hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	fp, err := agent.HookFingerprint("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	state := live.State{VerifiedAt: &now, Fingerprint: fp, CLIVersion: Version}
	if err := db.WriteLiveState(live.Key("claude-code", "/repo"), state); err != nil {
		t.Fatal(err)
	}
	if label := lastLiveLabel(db, "claude-code", "/repo"); strings.Contains(label, "STALE") {
		t.Fatal(label)
	}
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	label := lastLiveLabel(db, "claude-code", "/repo")
	if !strings.Contains(label, "STALE: configured command missing") || !strings.Contains(label, "last verified") {
		t.Fatal(label)
	}
	if _, _, err := liveConfiguration("claude-code"); err == nil || !strings.Contains(err.Error(), "configured command missing") {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("configuration changed")
	}
}

func TestLastLiveReportsCurrentScopeWithoutChangingHistory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	repo := t.TempDir()
	if output, err := exec.Command("git", "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, output)
	}
	root, err := repository.ResolveCurrent(repo)
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	state := live.State{Agent: "claude-code", Repository: root.Root, VerifiedAt: &now, CLIVersion: Version}
	key := live.Key(state.Agent, root.Root)
	if err := db.WriteLiveState(key, state); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{CaptureScope: config.CaptureScopeApproved, ApprovedRepositories: []string{root.Root}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if label := lastLiveLabel(db, state.Agent, root.Root); strings.Contains(label, "excluded by scope") {
		t.Fatal(label)
	}
	cfg.ApprovedRepositories = nil
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	label := lastLiveLabel(db, state.Agent, root.Root)
	if !strings.Contains(label, "last verified "+now.Format(time.RFC3339)) || !strings.Contains(label, "capture currently excluded by scope (unapproved_repository)") {
		t.Fatal(label)
	}
	// Scope must remain visible alongside hook dependency diagnostics.
	if !strings.Contains(label, "STALE: hook configuration missing") {
		t.Fatal(label)
	}
	var saved live.State
	found, err := db.ReadLiveState(key, &saved)
	if err != nil || !found || saved.VerifiedAt == nil || !saved.VerifiedAt.Equal(now) {
		t.Fatalf("historical verification changed: %+v %v", saved, err)
	}
	cfg.CaptureScope = config.CaptureScopeAll
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if label := lastLiveLabel(db, state.Agent, root.Root); strings.Contains(label, "excluded by scope") {
		t.Fatal(label)
	}
	configPath, err := config.DefaultConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("invalid json"), 0600); err != nil {
		t.Fatal(err)
	}
	label = lastLiveLabel(db, state.Agent, root.Root)
	if !strings.Contains(label, "current capture scope unavailable") || !strings.Contains(label, "last verified "+now.Format(time.RFC3339)) {
		t.Fatal(label)
	}
}
