package capture

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/events"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func TestComputeFileHash(t *testing.T) {
	t.Run("empty path returns empty string", func(t *testing.T) {
		if got := computeFileHash(""); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("nonexistent file returns empty string", func(t *testing.T) {
		if got := computeFileHash("/nonexistent/path/file.txt"); got != "" {
			t.Errorf("expected empty for missing file, got %q", got)
		}
	})

	t.Run("real file returns correct SHA-256", func(t *testing.T) {
		content := []byte("hello secuarden\n")
		f, err := os.CreateTemp(t.TempDir(), "*.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(content); err != nil {
			t.Fatal(err)
		}
		f.Close()

		want := fmt.Sprintf("%x", sha256.Sum256(content))
		got := computeFileHash(f.Name())
		if got != want {
			t.Errorf("hash mismatch: got %q, want %q", got, want)
		}
	})

	t.Run("sensitive file still gets hashed", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".env")
		if err := os.WriteFile(path, []byte("SECRET=abc"), 0600); err != nil {
			t.Fatal(err)
		}
		got := computeFileHash(path)
		if got == "" {
			t.Error("expected non-empty hash for sensitive file — content_hash is stored even for sensitive files per spec")
		}
	})
}

func TestClaudeOutcomeDoesNotInferPermissionAllowed(t *testing.T) {
	tests := []struct {
		phase, result, outcome, permission, execution string
	}{
		{events.HookPhasePre, "", "pending", "unknown", "not_started"},
		{events.HookPhasePost, events.ResultSuccess, "success", "unknown", "completed"},
		{events.HookPhasePost, events.ResultError, "error", "unknown", "failed"},
	}
	for _, tt := range tests {
		outcome, permission, execution := outcomeForPhase(tt.phase, tt.result)
		if outcome != tt.outcome || permission != tt.permission || execution != tt.execution {
			t.Fatalf("%s/%s = %s/%s/%s", tt.phase, tt.result, outcome, permission, execution)
		}
	}
}

func TestDemoFixtureCaptureContainsRequiredEvidence(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fixtures := filepath.Join("..", "..", "docs", "demo", "fixtures")
	steps := []struct{ phase, name string }{
		{"session-start", "01-session-start.json"},
		{"pre-tool-use", "02-read.json"},
		{"pre-tool-use", "03-sensitive-read.json"},
		{"post-tool-use", "03-sensitive-read-post.json"},
		{"pre-tool-use", "04-edit.json"},
		{"pre-tool-use", "05-command-pre.json"},
		{"post-tool-use", "06-command-post.json"},
		{"pre-tool-use", "07-mcp.json"},
		{"post-tool-use", "07-mcp-post.json"},
		{"session-end", "08-session-end.json"},
	}
	for _, step := range steps {
		replayHookFixture(t, step.phase, filepath.Join(fixtures, step.name))
	}
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	captured, err := db.QueryEvents(storage.EventFilter{SessionID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(captured) != len(steps) {
		t.Fatalf("captured %d events, want %d", len(captured), len(steps))
	}
	seen := map[string]bool{}
	for _, event := range captured {
		seen[event.ActionType] = true
		seen[event.HookPhase] = true
		if event.HookPhase == events.HookPhasePost && event.PermissionStatus != "unknown" {
			t.Fatalf("post event inferred permission %q", event.PermissionStatus)
		}
	}
	for _, want := range []string{events.ActionFileRead, events.ActionFileWrite, events.ActionCommandExec, events.ActionMCPToolUse, events.HookPhaseSessionStart, events.HookPhaseSessionEnd} {
		if !seen[want] {
			t.Errorf("demo evidence missing %s", want)
		}
	}
}

func TestMetadataOnlyOmitsContentFromPersistence(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := config.Save(&config.Config{PrivacyMode: "metadata_only"}); err != nil {
		t.Fatal(err)
	}
	replayHookFixture(t, "post-tool-use", filepath.Join("..", "..", "docs", "demo", "fixtures", "06-command-post.json"))
	dbPath, _ := storage.DefaultDBPath()
	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	captured, err := db.QueryEvents(storage.EventFilter{Limit: 10})
	if err != nil || len(captured) != 1 {
		t.Fatalf("events=%d err=%v", len(captured), err)
	}
	e := captured[0]
	if e.PrivacyMode != "metadata_only" || e.Command != "" || e.CommandOutputPreview != "" || e.DiffStats != "" {
		t.Fatalf("metadata-only event retained content: %#v", e)
	}
}

func replayHookFixture(t *testing.T, phase, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	os.Stdin = f
	err = handle(phase, "test")
	os.Stdin = oldStdin
	_ = f.Close()
	if err != nil {
		t.Fatalf("replay %s: %v", filepath.Base(path), err)
	}
}
