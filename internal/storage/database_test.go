package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/events"
)

func TestReadSessionEnvelopeContainsOrderedRedactedEvidence(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.EnsureSession("envelope", "claude-code", "/work"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateSessionIdentity("envelope", SessionIdentity{DeveloperName: "Dev", DeveloperEmail: "dev@example.invalid", GitBranch: "main"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range []*events.Event{
		{ID: "one", SessionID: "envelope", Timestamp: "2026-08-01T00:00:01Z", Source: "secuarden-cli", AgentName: "claude-code", HookPhase: "pre", ActionType: "command_exec", Command: "echo [REDACTED:token]", PrivacyMode: "redacted_content", RedactedFields: []string{"command"}},
		{ID: "two", SessionID: "envelope", Timestamp: "2026-08-01T00:00:02Z", Source: "secuarden-cli", AgentName: "claude-code", HookPhase: "post", ActionType: "mcp_tool_use", MCPServer: "docs", MCPTool: "lookup", Outcome: "success", PrivacyMode: "redacted_content", RedactedFields: []string{}},
	} {
		if err := db.WriteEvent(e); err != nil {
			t.Fatal(err)
		}
	}

	first, err := db.ReadSessionEnvelope("envelope")
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.ReadSessionEnvelope("envelope")
	if err != nil {
		t.Fatal(err)
	}
	if first.SchemaVersion != SessionEnvelopeVersion || first.DeveloperName != "Dev" || len(first.Events) != 2 {
		t.Fatalf("incomplete envelope: %#v", first)
	}
	if first.Events[0].Sequence != 1 || first.Events[1].Sequence != 2 || first.Events[1].MCPTool != "lookup" {
		t.Fatalf("events not ordered/complete: %#v", first.Events)
	}
	if first.Events[0].Command != "echo [REDACTED:token]" || len(first.Events[0].RedactedFields) != 1 {
		t.Fatal("stored redaction metadata was not preserved")
	}
	if first.Events[1].PreviousEventHash == "" || first.Events[1].EventHash == "" {
		t.Fatal("integrity chain missing")
	}
	if first.IdempotencyKey == "" || first.IdempotencyKey != second.IdempotencyKey {
		t.Fatal("idempotency key is not stable")
	}
}

func TestGeneratedSessionEnvelopeFixture(t *testing.T) {
	raw, err := os.ReadFile("../../fixtures/upload/v1/session-envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope SessionEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Schema != SessionEnvelopeSchemaURL || envelope.SchemaVersion != SessionEnvelopeVersion || len(envelope.Events) == 0 {
		t.Fatalf("invalid generated fixture: %#v", envelope)
	}
}

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

func canonicalToolEvent(id, session, phase, invocation string) *events.Event {
	outcome, execution := "pending", "not_started"
	if phase == events.HookPhasePost {
		outcome, execution = "success", "completed"
	}
	completeness := events.Completeness{State: "complete", Reasons: []string{}}
	if invocation == "" {
		completeness = events.Completeness{State: "partial", Reasons: []string{"missing_invocation_id"}}
	}
	return &events.Event{Schema: events.SchemaURL, SchemaVersion: events.SchemaVersion, ID: id, SessionID: session,
		Timestamp: "2026-07-31T01:02:03Z", CapturedAt: "2026-07-31T01:02:03Z", InvocationID: invocation,
		Source: "secuarden-cli", SourceVersion: "test", AgentName: "claude-code", HookPhase: phase,
		ActionType: events.ActionFileRead, ToolName: "Read", Outcome: outcome, PermissionStatus: "unknown",
		ExecutionStatus: execution, PrivacyMode: "metadata_only", Completeness: completeness,
		RedactedFields: []string{}, RawEventHash: strings.Repeat("a", 64)}
}

func TestPartialEventMissingInvocationPersists(t *testing.T) {
	db, _ := tempDB(t)
	_ = db.EnsureSession("partial", "claude-code", "/tmp")
	if err := db.WriteEvent(canonicalToolEvent("partial-pre", "partial", events.HookPhasePre, "")); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM events WHERE session_id='partial' AND completeness_state='partial'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("partial events=%d, want 1", count)
	}
}

func TestCaptureFailureAffectsHealthAndCompleteness(t *testing.T) {
	db, _ := tempDB(t)
	_ = db.EnsureSession("failed", "claude-code", "/tmp")
	if err := db.RecordCaptureFailure("failed", "post", "event_persistence_rejected"); err != nil {
		t.Fatal(err)
	}
	var failures int
	var state, reasons string
	if err := db.db.QueryRow(`SELECT capture_failure_count, completeness_state, completeness_reasons FROM sessions WHERE id='failed'`).Scan(&failures, &state, &reasons); err != nil {
		t.Fatal(err)
	}
	if failures != 1 || state != "partial" || !strings.Contains(reasons, "capture_error") {
		t.Fatalf("got failures=%d state=%s reasons=%s", failures, state, reasons)
	}
	var category string
	if err := db.db.QueryRow(`SELECT category FROM capture_failures WHERE session_id='failed'`).Scan(&category); err != nil {
		t.Fatal(err)
	}
	if category != "event_persistence_rejected" {
		t.Fatalf("unsafe/unexpected category %q", category)
	}
}

func TestCaptureFailureSanitizesUntrustedDetails(t *testing.T) {
	db, _ := tempDB(t)
	_ = db.EnsureSession("sanitized", "claude-code", "/tmp")
	secret := "pasted command and token must not survive"
	if err := db.RecordCaptureFailure("sanitized", secret, secret); err != nil {
		t.Fatal(err)
	}
	var phase, category string
	if err := db.db.QueryRow(`SELECT hook_phase, category FROM capture_failures WHERE session_id='sanitized'`).Scan(&phase, &category); err != nil {
		t.Fatal(err)
	}
	if phase != "unknown" || category != "capture_error" || strings.Contains(phase+category, secret) {
		t.Fatalf("unsanitized failure phase=%q category=%q", phase, category)
	}
}

func TestReconcileCorrelatedAndUnmatchedEvents(t *testing.T) {
	db, _ := tempDB(t)
	_ = db.EnsureSession("pairs", "claude-code", "/tmp")
	for _, e := range []*events.Event{
		canonicalToolEvent("pre-pair", "pairs", events.HookPhasePre, "pair"), canonicalToolEvent("post-pair", "pairs", events.HookPhasePost, "pair"),
		canonicalToolEvent("pre-only", "pairs", events.HookPhasePre, "pre-only"), canonicalToolEvent("post-only", "pairs", events.HookPhasePost, "post-only"),
	} {
		if err := db.WriteEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.ReconcileSessionCompleteness("pairs"); err != nil {
		t.Fatal(err)
	}
	var state, reasons string
	if err := db.db.QueryRow(`SELECT completeness_state, completeness_reasons FROM sessions WHERE id='pairs'`).Scan(&state, &reasons); err != nil {
		t.Fatal(err)
	}
	if state != "partial" || !strings.Contains(reasons, "missing_pre_event") || !strings.Contains(reasons, "missing_post_event") {
		t.Fatalf("state=%s reasons=%s", state, reasons)
	}
}

func TestWriteEventAllocatesIndependentSessionSequences(t *testing.T) {
	db, _ := tempDB(t)
	for _, sessionID := range []string{"sess-1", "sess-2"} {
		if err := db.EnsureSession(sessionID, "claude-code", "/tmp"); err != nil {
			t.Fatal(err)
		}
	}

	writes := []*events.Event{
		{ID: "s1-event-1", SessionID: "sess-1"},
		{ID: "s1-event-2", SessionID: "sess-1"},
		{ID: "s2-event-1", SessionID: "sess-2"},
	}
	for _, event := range writes {
		event.Timestamp = "2026-05-27T10:00:00Z"
		event.Source = "secuarden-cli"
		event.AgentName = "claude-code"
		event.HookPhase = events.HookPhasePre
		event.ActionType = events.ActionCommandExec
		event.Sequence = 999 // WriteEvent must ignore caller-provided allocation.
		if err := db.WriteEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	if writes[0].Sequence != 1 || writes[1].Sequence != 2 || writes[2].Sequence != 1 {
		t.Fatalf("unexpected allocated sequences: %d, %d, %d",
			writes[0].Sequence, writes[1].Sequence, writes[2].Sequence)
	}
}

func TestPendingSyncSessionsTrackSuccessfulEventCount(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.EnsureSession("sync-session", "claude-code", "/tmp"); err != nil {
		t.Fatal(err)
	}
	write := func(id string) {
		t.Helper()
		if err := db.WriteEvent(&events.Event{
			ID: id, SessionID: "sync-session", Timestamp: "2026-07-30T10:00:00Z",
			Source: "secuarden-cli", AgentName: "claude-code",
			HookPhase: events.HookPhasePost, ActionType: events.ActionFileWrite,
		}); err != nil {
			t.Fatal(err)
		}
	}

	write("sync-event-1")
	pending, err := db.ListPendingSyncSessions(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].SessionID != "sync-session" ||
		pending[0].EventCount != 1 || pending[0].LastSyncedEventCount != 0 {
		t.Fatalf("unexpected initial pending state: %#v", pending)
	}
	if err := db.RecordSyncSuccess("sync-session", 1); err != nil {
		t.Fatal(err)
	}
	pending, err = db.ListPendingSyncSessions(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("synced session remained pending: %#v", pending)
	}

	write("sync-event-2")
	pending, err = db.ListPendingSyncSessions(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].EventCount != 2 ||
		pending[0].LastSyncedEventCount != 1 {
		t.Fatalf("new event did not make session pending: %#v", pending)
	}
}

func TestWriteEventConcurrentSingleLinearChain(t *testing.T) {
	const (
		rounds = 3
		writes = 40
	)
	for round := 0; round < rounds; round++ {
		t.Run(fmt.Sprintf("round-%d", round+1), func(t *testing.T) {
			db, path := tempDB(t)
			if err := db.EnsureSession("concurrent-session", "claude-code", "/tmp/project"); err != nil {
				t.Fatal(err)
			}

			handles := make([]*DB, writes)
			for i := range handles {
				handle, err := Open(path)
				if err != nil {
					t.Fatal(err)
				}
				handles[i] = handle
				t.Cleanup(func() { _ = handle.Close() })
			}

			start := make(chan struct{})
			errs := make(chan error, writes)
			var wg sync.WaitGroup
			for i, handle := range handles {
				wg.Add(1)
				go func(index int, writer *DB) {
					defer wg.Done()
					<-start
					event := &events.Event{
						ID: fmt.Sprintf("concurrent-%02d", index), SessionID: "concurrent-session",
						Timestamp: "2026-05-27T10:00:00Z", Source: "secuarden-cli",
						AgentName: "claude-code", HookPhase: events.HookPhasePost,
						ActionType: events.ActionFileWrite, FilePath: fmt.Sprintf("file-%02d.go", index),
						ContentHash: fmt.Sprintf("sha256:%02d", index), RawEventHash: fmt.Sprintf("raw-%02d", index),
					}
					errs <- writer.WriteEvent(event)
				}(i, handle)
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Errorf("concurrent write failed: %v", err)
				}
			}
			if t.Failed() {
				return
			}

			rows, err := db.db.Query(`SELECT sequence, COALESCE(previous_event_hash, ''), event_hash
				FROM events WHERE session_id = ? ORDER BY sequence`, "concurrent-session")
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			count := 0
			previousHash := ""
			for rows.Next() {
				count++
				var sequence int
				var storedPrevious, eventHash string
				if err := rows.Scan(&sequence, &storedPrevious, &eventHash); err != nil {
					t.Fatal(err)
				}
				if sequence != count {
					t.Fatalf("sequence %d at position %d; want contiguous 1..%d", sequence, count, writes)
				}
				if storedPrevious != previousHash {
					t.Fatalf("sequence %d links to %q; want %q", sequence, storedPrevious, previousHash)
				}
				previousHash = eventHash
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if count != writes {
				t.Fatalf("stored %d successful writes; want %d", count, writes)
			}
			result, err := db.VerifyIntegrity()
			if err != nil || !result.Valid || result.EventsChecked != writes {
				t.Fatalf("concurrent chain did not verify: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestOpenSequenceUniquenessMigrationPreservesDuplicates(t *testing.T) {
	file, err := os.CreateTemp("", "secuarden-migration-*.db")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	file.Close()
	t.Cleanup(func() { _ = os.Remove(path) })

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(sqlSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO sessions (id, started_at) VALUES ('legacy-session', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO events
		(id, session_id, sequence, timestamp, source, agent_name, hook_phase, action_type)
		VALUES
		('legacy-1', 'legacy-session', 1, '2026-01-01T00:00:00Z', 'secuarden-cli', 'claude-code', 'pre', 'file_read'),
		('legacy-2', 'legacy-session', 1, '2026-01-01T00:00:01Z', 'secuarden-cli', 'claude-code', 'post', 'file_read')`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	if migrated, err := Open(path); err == nil {
		_ = migrated.Close()
		t.Fatal("expected duplicate sequence migration to fail")
	} else if !strings.Contains(err.Error(), "no events were removed") {
		t.Fatalf("migration error does not explain preservation: %v", err)
	}

	raw, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := raw.QueryRow(`SELECT COUNT(*) FROM events WHERE session_id = 'legacy-session' AND sequence = 1`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("migration discarded captured events: got %d, want 2", count)
	}
	if _, err := raw.Exec(`DELETE FROM events WHERE id = 'legacy-2'`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	migrated, err := Open(path)
	if err != nil {
		t.Fatalf("migration after duplicate resolution: %v", err)
	}
	defer migrated.Close()
	if _, err := migrated.db.Exec(`INSERT INTO events
		(id, session_id, sequence, timestamp, source, agent_name, hook_phase, action_type)
		VALUES ('duplicate', 'legacy-session', 1, '2026-01-01T00:00:02Z',
		'secuarden-cli', 'claude-code', 'pre', 'file_read')`); err == nil {
		t.Fatal("unique session/sequence index was not created")
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
