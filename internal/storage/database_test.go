package storage

import (
	"os"
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/events"
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
			Source:    "secuarden-cli", AgentName: "claude-code",
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

func seedIntegrityChain(t *testing.T, db *DB) {
	t.Helper()
	if err := db.EnsureSession("sess-chain", "claude-code", "/tmp/project"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`UPDATE sessions SET agent_version = ?, model = ? WHERE id = ?`,
		"1.2.3", "test-model", "sess-chain"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateSessionIdentity("sess-chain", SessionIdentity{
		DeveloperName: "Test Developer", DeveloperEmail: "dev@example.com",
		OSUser: "test-user", MachineID: "machine-1", GitBranch: "main",
		GitRepoURL: "https://example.com/acme/repo.git",
	}); err != nil {
		t.Fatal(err)
	}
	exitCode := 0
	duration := int64(25)
	for i := 1; i <= 2; i++ {
		e := &events.Event{
			ID: "chain-" + string(rune('0'+i)), SessionID: "sess-chain", Sequence: i,
			Timestamp: "2026-05-27T10:00:0" + string(rune('0'+i)) + "Z",
			Source:    "secuarden-cli", SourceVersion: "test", AgentName: "claude-code",
			HookPhase: events.HookPhasePost, ActionType: events.ActionFileWrite,
			ToolName: "Write", ResultStatus: events.ResultSuccess,
			IsSensitive: i == 2, RedactedFields: []string{"command_output_preview"},
			FilePath: "src/file.go", ContentHash: "sha256:content", DiffStats: "+1/-0",
			Command: "gofmt -w src/file.go", ExitCode: &exitCode,
			CommandOutputPreview: "formatted", MCPServer: "filesystem", MCPTool: "write",
			DurationMS: &duration, WorkingDirectory: "/tmp/project", GitBranch: "main",
			DeveloperEmail: "dev@example.com", IntentSummary: "format the file",
			RawEventHash: "sha256:raw",
		}
		if err := db.WriteEvent(e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVerifyIntegrityUntamperedMultiEventChain(t *testing.T) {
	db, _ := tempDB(t)
	seedIntegrityChain(t, db)
	result, err := db.VerifyIntegrity()
	if err != nil || !result.Valid || result.EventsChecked != 2 ||
		result.LegacyEvents != 0 || result.LegacySessions != 0 {
		t.Fatalf("expected valid two-event chain, result=%+v err=%v", result, err)
	}
}

func TestVerifyIntegrityDetectsEveryProtectedEventField(t *testing.T) {
	mutations := map[string]string{
		"id":                     "tampered-id",
		"session_id":             "tampered-session",
		"sequence":               "99",
		"timestamp":              "2026-06-01T00:00:00Z",
		"source":                 "manual",
		"source_version":         "tampered-version",
		"agent_name":             "codex",
		"hook_phase":             "pre",
		"action_type":            "command_exec",
		"tool_name":              "Bash",
		"result_status":          "error",
		"is_sensitive":           "0",
		"redacted_fields":        `["file_path"]`,
		"file_path":              "src/tampered.go",
		"content_hash":           "sha256:tampered",
		"diff_stats":             "+99/-99",
		"command":                "malicious command",
		"exit_code":              "42",
		"command_output_preview": "tampered output",
		"mcp_server":             "tampered-server",
		"mcp_tool":               "tampered-tool",
		"duration_ms":            "999",
		"working_directory":      "/tmp/tampered",
		"git_branch":             "tampered-branch",
		"developer_email":        "attacker@example.com",
		"intent_summary":         "tampered intent",
		"raw_event_hash":         "sha256:tampered-raw",
		"previous_event_hash":    "v2:tampered-previous",
	}

	for column, value := range mutations {
		t.Run(column, func(t *testing.T) {
			db, _ := tempDB(t)
			seedIntegrityChain(t, db)
			query := "UPDATE events SET " + column + " = ? WHERE id = 'chain-2'"
			if column == "id" || column == "session_id" {
				query = "PRAGMA foreign_keys=OFF"
				if _, err := db.db.Exec(query); err != nil {
					t.Fatal(err)
				}
				query = "UPDATE events SET " + column + " = ? WHERE id = 'chain-2'"
			}
			if _, err := db.db.Exec(query, value); err != nil {
				t.Fatal(err)
			}
			result, err := db.VerifyIntegrity()
			if err != nil {
				t.Fatal(err)
			}
			if result.Valid || len(result.Failures) == 0 {
				t.Fatalf("tampering with %s was not detected: %+v", column, result)
			}
		})
	}
}

func TestVerifyIntegrityDetectsProtectedSessionFields(t *testing.T) {
	mutations := map[string]string{
		"agent_name":        "codex",
		"agent_version":     "tampered-version",
		"model":             "tampered-model",
		"developer_name":    "Attacker",
		"developer_email":   "attacker@example.com",
		"os_user":           "attacker",
		"machine_id":        "tampered-machine",
		"working_directory": "/tmp/tampered",
		"git_repo_url":      "https://example.com/attacker/repo.git",
		"git_branch":        "tampered-branch",
	}
	for column, value := range mutations {
		t.Run(column, func(t *testing.T) {
			db, _ := tempDB(t)
			seedIntegrityChain(t, db)
			query := "UPDATE sessions SET " + column + " = ? WHERE id = 'sess-chain'"
			if _, err := db.db.Exec(query, value); err != nil {
				t.Fatal(err)
			}
			result, err := db.VerifyIntegrity()
			if err != nil {
				t.Fatal(err)
			}
			if result.Valid || !containsFailure(result.Failures, "session:sess-chain") {
				t.Fatalf("tampering with %s was not detected: %+v", column, result)
			}
		})
	}
}

func TestIntegrityHashesAreDeterministic(t *testing.T) {
	exitCode := 1
	duration := int64(10)
	event := &events.Event{
		ID: "event", SessionID: "session", Sequence: 1, Timestamp: "timestamp",
		Source: "source", SourceVersion: "version", AgentName: "agent",
		HookPhase: "post", ActionType: "file_write", ToolName: "Write",
		ResultStatus: "success", IsSensitive: true, FilePath: "file",
		ContentHash: "content", DiffStats: "diff", Command: "command",
		ExitCode: &exitCode, CommandOutputPreview: "output", MCPServer: "server",
		MCPTool: "tool", DurationMS: &duration, WorkingDirectory: "working",
		GitBranch: "branch", DeveloperEmail: "developer", IntentSummary: "intent",
		RawEventHash: "raw",
	}
	first, err := computeEventHashV2("previous", event, `["command"]`)
	if err != nil {
		t.Fatal(err)
	}
	second, err := computeEventHashV2("previous", event, `["command"]`)
	if err != nil || first != second || !strings.HasPrefix(first, eventHashPrefix) {
		t.Fatalf("event hashes are not deterministic: %q %q err=%v", first, second, err)
	}

	session := sessionIntegrityRecord{ID: "session", AgentName: "agent", Model: "model"}
	first, err = computeSessionHash(session)
	if err != nil {
		t.Fatal(err)
	}
	second, err = computeSessionHash(session)
	if err != nil || first != second || !strings.HasPrefix(first, sessionHashPrefix) {
		t.Fatalf("session hashes are not deterministic: %q %q err=%v", first, second, err)
	}
}

func TestVerifyIntegrityIdentifiesLegacyFormats(t *testing.T) {
	db, _ := tempDB(t)
	seedIntegrityChain(t, db)
	if _, err := db.db.Exec(`UPDATE events SET event_hash = ?, previous_event_hash = NULL
		WHERE id = 'chain-1'`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`UPDATE events SET event_hash = NULL, previous_event_hash = NULL
		WHERE id = 'chain-2'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`UPDATE sessions SET session_hash = NULL WHERE id = 'sess-chain'`); err != nil {
		t.Fatal(err)
	}
	result, err := db.VerifyIntegrity()
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.LegacyEvents != 2 || result.LegacySessions != 1 ||
		!containsFailure(result.Failures, "legacy:sess-chain:1") ||
		!containsFailure(result.Failures, "legacy-session:sess-chain") {
		t.Fatalf("legacy records were not identified correctly: %+v", result)
	}
}

func containsFailure(failures []string, want string) bool {
	for _, failure := range failures {
		if failure == want {
			return true
		}
	}
	return false
}
