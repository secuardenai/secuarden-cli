package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/events"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func testServer(t *testing.T) (*storage.DB, http.Handler) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.EnsureSession("session-one", "claude-code", "/work/demo"); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteEvent(&events.Event{
		ID: "event-one", SessionID: "session-one", Timestamp: "2026-08-01T01:02:03Z",
		Source: "secuarden-cli", AgentName: "claude-code", HookPhase: "post",
		ActionType: "file_read", ToolName: "Read", FilePath: "README.md",
	}); err != nil {
		t.Fatal(err)
	}
	return db, New(db, "test-version").Handler()
}

func TestDashboardSummaryAndDrilldown(t *testing.T) {
	db, handler := testServer(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, event := range []events.Event{
		{ID: "today-write", SessionID: "session-one", Timestamp: now, Source: "secuarden-cli", AgentName: "claude-code", HookPhase: "post", ActionType: "file_write", FilePath: "main.go", ResultStatus: "success", Outcome: "success", ExecutionStatus: "completed"},
		{ID: "today-error", SessionID: "session-one", Timestamp: now, Source: "secuarden-cli", AgentName: "claude-code", HookPhase: "post", ActionType: "command_exec", Command: "go test ./...", ResultStatus: "error"},
	} {
		if err := db.WriteEvent(&event); err != nil {
			t.Fatal(err)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/overview", nil))
	var overview struct {
		Summary storage.StatusSummary `json:"summary"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || overview.Summary.Today.Actions != 2 || overview.Summary.Dashboard.Errors != 1 || overview.Summary.Dashboard.CommandFailed != 1 || len(overview.Summary.Dashboard.Timeline) != 24 {
		t.Fatalf("dashboard status=%d summary=%+v", response.Code, overview.Summary)
	}
	for _, test := range []struct{ query, id string }{
		{"changes=true&file=main.go", "today-write"},
		{"failures=true", "today-error"},
		{"agent=claude-code&action=command_exec", "today-error"},
		{"command=go+test+.%2F...", "today-error"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/events?"+test.query, nil))
		var got []storage.StoredEvent
		if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusOK || len(got) != 1 || got[0].ID != test.id {
			t.Errorf("query=%s status=%d events=%+v", test.query, response.Code, got)
		}
	}
}

func TestDashboardAndSecurityHeaders(t *testing.T) {
	_, handler := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Secuarden Local Evidence") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Cache-Control"} {
		if response.Header().Get(header) == "" {
			t.Errorf("missing %s", header)
		}
	}
}

func TestEventsAPIAndFilters(t *testing.T) {
	_, handler := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "/api/events?action=file_read&session=session-one", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var result []storage.StoredEvent
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(result) != 1 || result[0].FilePath != "README.md" {
		t.Fatalf("status=%d result=%#v", response.Code, result)
	}

	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/api/events?limit=1001", nil))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("bad limit status=%d", bad.Code)
	}
}

func TestSessionAPIAndReadOnlyMethods(t *testing.T) {
	_, handler := testServer(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/sessions/session-one", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "session-one") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/events", strings.NewReader("{}")))
	if response.Code != http.StatusNotFound && response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("write method status=%d", response.Code)
	}
}

func TestDashboardTimeFilterValidation(t *testing.T) {
	_, handler := testServer(t)
	for _, query := range []string{"since=invalid", "until=invalid", "since=2026-10-10T00:00:00Z&until=2026-10-09T00:00:00Z", "since=2026-10-10T00:00:00Z&until=2026-10-10T00:00:00Z"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/events?"+query, nil))
		if response.Code != http.StatusBadRequest {
			t.Errorf("query=%s status=%d", query, response.Code)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/overview", nil))
	var got overview
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	start, err := time.Parse(time.RFC3339, got.PeriodStart)
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC3339, got.PeriodEnd)
	if err != nil || !start.Before(end) {
		t.Fatalf("invalid period: %+v", got)
	}
}
