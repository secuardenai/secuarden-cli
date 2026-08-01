package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
