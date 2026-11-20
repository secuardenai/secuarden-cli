package chain

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/events"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func TestBuildJoinsPromptFindingAndCommit(t *testing.T) {
	root := t.TempDir()
	gitCmd(t, root, "init", "-q", "-b", "main")
	gitCmd(t, root, "config", "user.email", "dev@example.com")
	gitCmd(t, root, "config", "user.name", "Dev")
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("base\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, root, "add", "README")
	gitCmd(t, root, "commit", "-q", "-m", "base")
	base := gitCmd(t, root, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte("def private():\n    return 'ok'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, root, "add", "app.py")
	gitCmd(t, root, "commit", "-q", "-m", "remove the login check")
	head := gitCmd(t, root, "rev-parse", "HEAD")

	t.Setenv("HOME", t.TempDir())
	db := openDB(t)
	defer db.Close()
	eventID := mustEdit(t, db, root)
	if err := db.SaveEditRevision(storage.EditRevision{EventID: eventID, SessionID: "s", Path: "app.py", Before: "@login_required", After: ""}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveFindings([]storage.PostureFinding{{
		ID: "f1", EventID: eventID, SessionID: "s", Kind: "control_relaxed", Path: "app.py",
		PromptExcerpt: "disable the login check so the demo works",
		Explanation:   "The prompt asks to bypass a control, and the edit relaxes one.",
	}}); err != nil {
		t.Fatal(err)
	}
	report, err := Build(db, root, base, "", head)
	if err != nil {
		t.Fatal(err)
	}
	if report.Integrity != "checksum" || len(report.Entries) != 1 {
		t.Fatalf("report = %#v", report)
	}
	entry := report.Entries[0]
	if !entry.Committed || entry.Commit != head || entry.Path != "app.py" || !entry.PromptCaptured || len(entry.Findings) != 1 {
		t.Fatalf("entry = %#v", entry)
	}
}

func mustEdit(t *testing.T, db *storage.DB, root string) string {
	t.Helper()
	if err := db.EnsureSession("s", "claude-code", root); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	event := &events.Event{
		Schema: events.SchemaURL, SchemaVersion: events.SchemaVersion,
		ID: "edit-1", SessionID: "s", Timestamp: now, CapturedAt: now,
		InvocationID: "inv-1", Source: "secuarden-cli", SourceVersion: "test",
		AgentName: "claude-code", HookPhase: events.HookPhasePost, ActionType: events.ActionFileWrite,
		ToolName: "Edit", Outcome: "success", PermissionStatus: "unknown", ExecutionStatus: "completed",
		PrivacyMode: "redacted_content", Completeness: events.Completeness{State: "complete", Reasons: []string{}},
		FilePath: "app.py", WorkingDirectory: root, IntentSummary: "disable the login check so the demo works",
		RawEventHash: strings.Repeat("ab", 32),
	}
	if err := db.WriteEvent(event); err != nil {
		t.Fatal(err)
	}
	return event.ID
}

func gitCmd(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func openDB(t *testing.T) *storage.DB {
	t.Helper()
	path, err := storage.DefaultDBPath()
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}
