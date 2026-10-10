package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/secuardenai/secuarden-cli/internal/events"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRenderSessionKeepsLargeCaptureReadable(t *testing.T) {
	session := &storage.SessionInvestigation{
		SessionID: "sample", Agent: "codex", StartedAt: "2026-10-04T03:35:30Z", EventCount: 652,
		CountsByAction: []storage.CountByAction{{ActionType: "command_exec", Count: 503}, {ActionType: "file_write", Count: 90}},
		Intents:        []string{"Improve the dashboard", "  Review the findings\nand fix the layout  "},
	}
	for i := 0; i < 503; i++ {
		session.Commands = append(session.Commands, storage.CommandActivity{Command: fmt.Sprintf("command-%d", i)})
	}
	var out bytes.Buffer
	if err := renderSession(&out, session); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Total                     652", "90 write events have no confirmed file changes", "Review the findings and fix the layout", "command-502", "+499 earlier commands", "--full"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "command-0\n") || strings.Count(out.String(), "command-") != 4 {
		t.Fatalf("summary expanded old commands:\n%s", out.String())
	}
	out.Reset()
	if err := renderSessionFull(&out, session); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "command-0 · outcome not captured") {
		t.Fatal("full view omitted historical command detail")
	}
}

func TestRenderSessionFitsNarrowTerminalAndGroupsTools(t *testing.T) {
	t.Setenv("COLUMNS", "60")
	session := &storage.SessionInvestigation{
		SessionID: "s1", Agent: "codex", Repository: "git@example.com:owner/a-repository-with-a-long-name.git",
		StartedAt: "2026-10-04T03:35:30Z", EventCount: 3,
		Intents:  []string{"Review https://example.com/this/is/a/very/long/unbroken/reference/that/exceeds/the/terminal/width"},
		Commands: []storage.CommandActivity{{Command: "go test ./...", Status: "success"}},
		MCPTools: []storage.MCPActivity{{Tool: "js", Server: "cua_repl"}, {Tool: "js", Server: "cua_repl"}},
	}
	var out bytes.Buffer
	if err := renderSession(&out, session); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		if utf8.RuneCountInString(line) > 60 {
			t.Fatalf("line exceeds 60 columns: %q", line)
		}
	}
	if !strings.Contains(out.String(), "2  cua_repl/js") || strings.Count(out.String(), "cua_repl/js") != 1 {
		t.Fatalf("MCP calls were not grouped:\n%s", out.String())
	}
}

func TestSessionCLIJSONFullAndIntentStorage(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	db, err := storage.Open(filepath.Join(home, ".secuarden", "secuarden.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureSession("layout-session", "codex", "/repo"); err != nil {
		t.Fatal(err)
	}
	event := events.Event{ID: "intent", SessionID: "layout-session", Schema: events.SchemaURL, SchemaVersion: events.SchemaVersion, Source: "secuarden-cli", AgentName: "codex", Timestamp: "2026-10-04T00:00:00Z", ActionType: "developer_intent", HookPhase: "user_prompt_submit", IntentSummary: "Review the captured intent"}
	if err := db.WriteEvent(&event); err != nil {
		t.Fatal(err)
	}
	db.Close()
	summary, err := ledgerProcess("session", "layout-session")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summary), "CAPTURED INTENT") || !strings.Contains(string(summary), event.IntentSummary) {
		t.Fatalf("%s", summary)
	}
	full, err := ledgerProcess("session", "layout-session", "--full")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(full), "Secuarden Session") || !strings.Contains(string(full), "Repository baseline:") {
		t.Fatalf("%s", full)
	}
	data, err := ledgerProcess("session", "layout-session", "--full", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal("--json did not take precedence over --full:", err)
	}
	for _, field := range []string{"session_id", "event_count", "counts_by_action", "commands", "mcp_tools", "repository_checkpoints", "baseline_status", "end_checkpoint_status", "intents"} {
		if _, ok := got[field]; !ok {
			t.Fatalf("JSON lost %s", field)
		}
	}
	var intents []string
	if err := json.Unmarshal(got["intents"], &intents); err != nil || len(intents) != 1 || intents[0] != event.IntentSummary {
		t.Fatalf("%v %v", intents, err)
	}
}
