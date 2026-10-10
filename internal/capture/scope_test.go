package capture

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func TestOutOfScopeHookDoesNotPersistEventData(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	allowed := initCaptureRepository(t, "allowed")
	other := initCaptureRepository(t, "other")
	if err := config.Save(&config.Config{CaptureScope: config.CaptureScopeRepo, RepositoryRoot: allowed}); err != nil {
		t.Fatal(err)
	}
	replayCaptureJSON(t, `{"session_id":"outside","cwd":"`+other+`","hook_event_name":"SessionStart"}`)

	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	events, err := db.QueryEvents(storage.EventFilter{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("out-of-scope event persisted: %#v", events)
	}
	counts, err := db.ScopeSkipCounts()
	if err != nil {
		t.Fatal(err)
	}
	if counts["different_repository"] != 1 {
		t.Fatalf("scope skip counts = %#v", counts)
	}
}

func initCaptureRepository(t *testing.T, name string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := func(args ...string) {
		c := exec.Command("git", args...)
		c.Dir = root
		if output, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
	}
	cmd("init", "--quiet")
	return root
}

func replayCaptureJSON(t *testing.T, payload string) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "hook-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(payload); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	old := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = old }()
	if err := handle("session-start", "test"); err != nil {
		t.Fatal(err)
	}
}
