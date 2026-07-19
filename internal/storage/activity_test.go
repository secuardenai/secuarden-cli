package storage

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/events"
	_ "modernc.org/sqlite"
)

func writeActivityEvent(t *testing.T, db *DB, e events.Event) {
	t.Helper()
	if e.Schema == "" {
		e.Schema = events.SchemaURL
		e.SchemaVersion = events.SchemaVersion
		e.Source = "secuarden-cli"
		e.AgentName = "claude-code"
	}
	if err := db.WriteEvent(&e); err != nil {
		t.Fatalf("WriteEvent(%s): %v", e.ID, err)
	}
}

func intPtr(value int) *int { return &value }

func seedActivity(t *testing.T, db *DB) {
	t.Helper()
	if err := db.EnsureSession("session-a", "claude-code", "/work/demo"); err != nil {
		t.Fatal(err)
	}
	_, _ = db.db.Exec(`UPDATE sessions SET started_at = ?, ended_at = ?, developer_name = ?, developer_email = ?, git_repo_url = ?, git_branch = ? WHERE id = ?`,
		"2026-07-19T08:00:00Z", "2026-07-19T08:10:00Z", "Dev", "dev@example.com", "https://example.com/org/repo.git", "main", "session-a")
	base := events.Event{SessionID: "session-a", AgentName: "claude-code", Source: "secuarden-cli"}
	items := []events.Event{
		{ID: "e1", Sequence: 1, Timestamp: "2026-07-19T08:00:00Z", HookPhase: "pre", ActionType: "file_read", ToolName: "Read", FilePath: "README.md"},
		{ID: "e2", Sequence: 2, Timestamp: "2026-07-19T08:00:00.100Z", HookPhase: "post", ActionType: "file_read", ToolName: "Read", FilePath: "README.md", ResultStatus: "success"},
		{ID: "e3", Sequence: 3, Timestamp: "2026-07-19T08:01:00Z", HookPhase: "post", ActionType: "file_write", ToolName: "Edit", FilePath: "main.go", ResultStatus: "success"},
		{ID: "e4", Sequence: 4, Timestamp: "2026-07-19T08:02:00Z", HookPhase: "post", ActionType: "command_exec", ToolName: "Bash", Command: "go test ./...", ExitCode: intPtr(1), ResultStatus: "error"},
		{ID: "e5", Sequence: 5, Timestamp: "2026-07-19T08:03:00Z", HookPhase: "post", ActionType: "file_read", ToolName: "Read", FilePath: ".env.local", IsSensitive: true, RedactedFields: []string{"command_output_preview"}, ResultStatus: "success"},
		{ID: "e6", Sequence: 6, Timestamp: "2026-07-19T08:04:00Z", HookPhase: "pre", ActionType: "command_exec", ToolName: "Bash", Command: "deploy", ResultStatus: "blocked"},
		{ID: "e7", Sequence: 7, Timestamp: "2026-07-19T08:05:00Z", HookPhase: "post", ActionType: "mcp_tool_use", ToolName: "mcp__memory__create_entities", MCPServer: "memory", MCPTool: "create_entities", ResultStatus: "success"},
	}
	for _, item := range items {
		item.SessionID, item.AgentName, item.Source = base.SessionID, base.AgentName, base.Source
		writeActivityEvent(t, db, item)
	}
}

func TestQueryEventsCombinedFiltersAndOrdering(t *testing.T) {
	db, _ := tempDB(t)
	seedActivity(t, db)
	got, err := db.QueryEvents(EventFilter{ActionType: "file_read", SessionID: "session-a", Sensitive: true, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "e5" || !got[0].IsSensitive {
		t.Fatalf("unexpected filtered events: %#v", got)
	}
	latest, err := db.QueryEvents(EventFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 2 || latest[0].ID != "e6" || latest[1].ID != "e7" {
		t.Fatalf("latest events not chronological: %#v", latest)
	}
}

func TestStatusAggregationAndAttention(t *testing.T) {
	db, _ := tempDB(t)
	seedActivity(t, db)
	start := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	status, err := db.GetStatusSummary(start, start.Add(24*time.Hour), 3)
	if err != nil {
		t.Fatal(err)
	}
	if status.Today.Sessions != 1 || status.Today.Actions != 7 || status.Today.FilesRead != 2 || status.Today.FilesChanged != 1 {
		t.Fatalf("unexpected totals: %#v", status.Today)
	}
	if status.Today.Commands != 1 || status.Today.MCPCalls != 1 || status.Today.SensitiveAccesses != 1 {
		t.Fatalf("unexpected execution totals: %#v", status.Today)
	}
	kinds := map[string]bool{}
	for _, finding := range status.Attention {
		kinds[finding.Kind] = true
	}
	for _, want := range []string{"failed_command", "sensitive_access", "blocked_action"} {
		if !kinds[want] {
			t.Errorf("missing attention kind %q: %#v", want, status.Attention)
		}
	}
	if len(status.RecentSessions) != 1 || status.RecentSessions[0].Label != "main" {
		t.Fatalf("unexpected recent sessions: %#v", status.RecentSessions)
	}
}

func TestSessionAggregation(t *testing.T) {
	db, _ := tempDB(t)
	seedActivity(t, db)
	session, err := db.GetSessionInvestigation("session-a")
	if err != nil {
		t.Fatal(err)
	}
	if session.EventCount != 7 || session.DurationSeconds == nil || *session.DurationSeconds != 600 {
		t.Fatalf("unexpected session basics: %#v", session)
	}
	if len(session.Commands) != 1 || session.Commands[0].ExitCode == nil || *session.Commands[0].ExitCode != 1 {
		t.Fatalf("unexpected commands: %#v", session.Commands)
	}
	if len(session.MCPTools) != 1 || len(session.SensitiveAccesses) != 1 {
		t.Fatalf("unexpected activity: mcp=%#v sensitive=%#v", session.MCPTools, session.SensitiveAccesses)
	}
	if len(session.FilesRead) != 2 || len(session.FilesChanged) != 1 {
		t.Fatalf("unexpected files: read=%#v changed=%#v", session.FilesRead, session.FilesChanged)
	}
}

func TestAccountabilityReportAndEmptyDatabase(t *testing.T) {
	db, _ := tempDB(t)
	since := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	empty, err := db.GetAccountabilityReport(since, since.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if empty.Totals.Actions != 0 || empty.FilesRead == nil || empty.Attention == nil {
		t.Fatalf("empty report must use zero totals and JSON arrays: %#v", empty)
	}
	seedActivity(t, db)
	report, err := db.GetAccountabilityReport(since, since.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if report.Totals.Actions != 7 || report.CommandExecutions != 1 || report.CommandFailures != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if len(report.SensitiveAccesses) != 1 || len(report.MCPActivity) != 1 {
		t.Fatalf("unexpected report details: %#v", report)
	}
}

func TestReportPathEvidenceFallsBackToSessionWorkingDirectory(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.EnsureSession("relative-session", "claude-code", "/repo/nested"); err != nil {
		t.Fatal(err)
	}
	writeActivityEvent(t, db, events.Event{
		ID: "relative-event", SessionID: "relative-session", Sequence: 1,
		Timestamp: "2026-07-19T08:00:00Z", HookPhase: "post",
		ActionType: "file_write", FilePath: "src/file.go",
	})
	since := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	report, err := db.GetAccountabilityReportForSessions(since, since.Add(24*time.Hour), []string{"relative-session"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.PathEvidence) != 1 || report.PathEvidence[0].WorkingDirectory != "/repo/nested" {
		t.Fatalf("session working-directory fallback missing: %#v", report.PathEvidence)
	}
}

func TestOpenExistingSchemaDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(sqlSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO sessions (id, started_at) VALUES ('existing-session', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open existing database: %v", err)
	}
	defer db.Close()
	if _, err := db.GetSessionInvestigation("existing-session"); err != nil {
		t.Fatalf("query existing database: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
