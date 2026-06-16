package storage

import (
	"os"
	"testing"

	"github.com/secuarden/secuarden-cli/internal/events"
)

func tempDB(t *testing.T) (*DB, string) {
	t.Helper()
	f, err := os.CreateTemp("", "secuarden-test-*.db")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	f.Close()
	path := f.Name()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		os.Remove(path)
	})
	return db, path
}

func TestOpen(t *testing.T) {
	db, _ := tempDB(t)
	if db == nil {
		t.Fatal("expected non-nil db")
	}
}

func TestEnsureSession(t *testing.T) {
	db, _ := tempDB(t)
	err := db.EnsureSession("sess-1", "claude-code", "/tmp/project")
	if err != nil {
		t.Fatalf("EnsureSession: %v", err)
	}
	// Second call should be idempotent
	err = db.EnsureSession("sess-1", "claude-code", "/tmp/project")
	if err != nil {
		t.Fatalf("EnsureSession (idempotent): %v", err)
	}
}

func TestWriteEvent(t *testing.T) {
	db, _ := tempDB(t)
	_ = db.EnsureSession("sess-1", "claude-code", "/tmp/project")

	e := &events.Event{
		Schema:        events.SchemaURL,
		SchemaVersion: events.SchemaVersion,
		ID:            "evt-1",
		SessionID:     "sess-1",
		Sequence:      1,
		Timestamp:     "2026-05-27T10:00:00Z",
		Source:        "secuarden-cli",
		SourceVersion: "dev",
		AgentName:     "claude-code",
		HookPhase:     events.HookPhasePre,
		ActionType:    events.ActionCommandExec,
		ToolName:      "Bash",
		IsSensitive:   false,
		Command:       "npm test",
	}

	if err := db.WriteEvent(e); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
}

func TestNextSequence(t *testing.T) {
	db, _ := tempDB(t)
	_ = db.EnsureSession("sess-1", "claude-code", "/tmp")

	seq1, _ := db.NextSequence("sess-1")
	if seq1 != 1 {
		t.Errorf("expected seq=1, got %d", seq1)
	}

	e := &events.Event{
		Schema: events.SchemaURL, SchemaVersion: events.SchemaVersion,
		ID: "evt-1", SessionID: "sess-1", Sequence: 1,
		Timestamp: "2026-05-27T10:00:00Z", Source: "secuarden-cli",
		AgentName: "claude-code", HookPhase: events.HookPhasePre,
		ActionType: events.ActionCommandExec, IsSensitive: false,
	}
	_ = db.WriteEvent(e)

	seq2, _ := db.NextSequence("sess-1")
	if seq2 != 2 {
		t.Errorf("expected seq=2, got %d", seq2)
	}
}

func TestWriteEvent_Sensitive(t *testing.T) {
	db, _ := tempDB(t)
	_ = db.EnsureSession("sess-1", "claude-code", "/tmp")

	e := &events.Event{
		Schema: events.SchemaURL, SchemaVersion: events.SchemaVersion,
		ID: "evt-s", SessionID: "sess-1", Sequence: 1,
		Timestamp: "2026-05-27T10:00:00Z", Source: "secuarden-cli",
		AgentName: "claude-code", HookPhase: events.HookPhasePre,
		ActionType: events.ActionFileRead, ToolName: "Read",
		FilePath:       ".env",
		IsSensitive:    true,
		RedactedFields: []string{"command", "command_output_preview"},
		Command:        "", // should be empty for sensitive files
	}
	if err := db.WriteEvent(e); err != nil {
		t.Fatalf("WriteEvent sensitive: %v", err)
	}
}

func TestGetStats(t *testing.T) {
	db, path := tempDB(t)
	_ = db.EnsureSession("sess-1", "claude-code", "/tmp")

	for i := 1; i <= 3; i++ {
		e := &events.Event{
			Schema: events.SchemaURL, SchemaVersion: events.SchemaVersion,
			ID: "evt-" + string(rune('0'+i)), SessionID: "sess-1", Sequence: i,
			Timestamp: "2026-05-27T10:00:0" + string(rune('0'+i)) + "Z",
			Source: "secuarden-cli", AgentName: "claude-code",
			HookPhase: events.HookPhasePre, ActionType: events.ActionFileRead,
			IsSensitive: false,
		}
		_ = db.WriteEvent(e)
	}

	stats, err := db.GetStats(path)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.TotalSessions != 1 {
		t.Errorf("expected 1 session, got %d", stats.TotalSessions)
	}
	if stats.TotalEvents != 3 {
		t.Errorf("expected 3 events, got %d", stats.TotalEvents)
	}
}

func TestEndSession(t *testing.T) {
	db, _ := tempDB(t)
	_ = db.EnsureSession("sess-1", "claude-code", "/tmp")
	if err := db.EndSession("sess-1"); err != nil {
		t.Fatalf("EndSession: %v", err)
	}
}
