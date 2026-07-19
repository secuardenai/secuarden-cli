package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func TestParseTimeWindow(t *testing.T) {
	tests := map[string]time.Duration{
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"90m": 90 * time.Minute,
	}
	for input, want := range tests {
		got, err := parseTimeWindow(input)
		if err != nil || got != want {
			t.Errorf("parseTimeWindow(%q) = %v, %v; want %v", input, got, err, want)
		}
	}
	for _, input := range []string{"", "0h", "-1h", "xd"} {
		if _, err := parseTimeWindow(input); err == nil {
			t.Errorf("parseTimeWindow(%q) unexpectedly succeeded", input)
		}
	}
}

func TestJSONOutputValidityAndEmptyArray(t *testing.T) {
	var out bytes.Buffer
	if err := writeJSON(&out, []storage.StoredEvent{}); err != nil {
		t.Fatal(err)
	}
	var decoded []storage.StoredEvent
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	if strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("empty events JSON = %q, want []", out.String())
	}
}

func TestRenderEventsSensitiveAndNoTruncation(t *testing.T) {
	command := "go test ./... -run TestAReallyLongCommandThatMustRemainReadableWithoutEllipsis"
	events := []storage.StoredEvent{{
		Timestamp: "2026-07-19T10:00:00Z", ActionType: "command_exec",
		Command: command, IsSensitive: true,
	}}
	var out bytes.Buffer
	if err := renderEvents(&out, events); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), command+" [SENSITIVE]") || strings.Contains(out.String(), "…") {
		t.Fatalf("unexpected event output: %s", out.String())
	}
	out.Reset()
	_ = renderEvents(&out, []storage.StoredEvent{})
	if !strings.Contains(out.String(), "No events match") {
		t.Fatalf("unexpected empty output: %s", out.String())
	}
}

func TestRenderStatusAggregationAndCleanState(t *testing.T) {
	view := statusView{
		CaptureActive: true, Agent: "claude-code", DatabasePath: "/tmp/secuarden.db",
		DatabaseSize: 77824, Sync: "Local only", Developer: "Dev <dev@example.com>",
		Summary: &storage.StatusSummary{
			Today:     storage.ActivityCounts{Sessions: 3, Actions: 52, FilesRead: 14, FilesChanged: 6, Commands: 21, MCPCalls: 2, SensitiveAccesses: 1},
			Attention: []storage.AttentionFinding{}, RecentSessions: []storage.RecentSession{},
		},
	}
	var out bytes.Buffer
	if err := renderStatus(&out, view); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Capture: Active · Claude Code", "3 sessions · 52 actions", "None detected", "secuarden events", "secuarden report"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status missing %q:\n%s", want, out.String())
		}
	}
}

func TestAttentionSuffixesOnlyShowRelevantOutcomes(t *testing.T) {
	if got := findingSuffix(storage.AttentionFinding{Kind: "sensitive_access", Status: "success", ExitCode: intPointer(0)}); got != "" {
		t.Fatalf("successful sensitive access suffix = %q, want empty", got)
	}
	if got := findingSuffix(storage.AttentionFinding{Kind: "failed_command", ExitCode: intPointer(2)}); got != " · exit 2" {
		t.Fatalf("failed command suffix = %q", got)
	}
}

func intPointer(value int) *int { return &value }

func TestMarkdownReportOutput(t *testing.T) {
	report := &storage.AccountabilityReport{
		Since: "2026-07-18T00:00:00Z", Until: "2026-07-19T00:00:00Z",
		Totals:    storage.ActivityCounts{Sessions: 1, Actions: 4, FilesRead: 1},
		Agents:    []storage.NamedCount{{Name: "claude-code", Count: 4}},
		FilesRead: []string{"README.md"}, FilesChanged: []string{},
		SensitiveAccesses: []storage.StoredEvent{}, Attention: []storage.AttentionFinding{},
		MCPActivity: []storage.NamedCount{}, Developers: []storage.NamedCount{}, Branches: []storage.NamedCount{},
	}
	var out bytes.Buffer
	if err := renderReport(&out, report, true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Secuarden Local Accountability Report", "## Overall totals", "## Sensitive access", "- README.md", "- None captured."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("Markdown report missing %q:\n%s", want, out.String())
		}
	}
}

func TestTerminalReportTitleBanner(t *testing.T) {
	report := &storage.AccountabilityReport{
		Since: "2026-07-18T00:00:00Z", Until: "2026-07-19T00:00:00Z",
		Agents: []storage.NamedCount{}, FilesRead: []string{}, FilesChanged: []string{},
		SensitiveAccesses: []storage.StoredEvent{}, Attention: []storage.AttentionFinding{},
		MCPActivity: []storage.NamedCount{}, Developers: []storage.NamedCount{}, Branches: []storage.NamedCount{},
	}
	var out bytes.Buffer
	if err := renderReport(&out, report, false); err != nil {
		t.Fatal(err)
	}
	const title = "Secuarden Local Accountability Report"
	want := strings.Repeat("#", len(title)) + "\n" + title + "\n" + strings.Repeat("#", len(title))
	if !strings.HasPrefix(out.String(), want) {
		t.Fatalf("terminal report banner mismatch:\n%s", out.String())
	}
}

func TestRenderSessionSensitiveAndBlocked(t *testing.T) {
	session := &storage.SessionInvestigation{
		SessionID: "s1", Agent: "claude-code", StartedAt: "2026-07-19T00:00:00Z",
		CountsByAction: []storage.CountByAction{}, FilesRead: []string{}, FilesChanged: []string{},
		Commands: []storage.CommandActivity{}, MCPTools: []storage.MCPActivity{},
		SensitiveAccesses: []storage.StoredEvent{{ActionType: "file_read", FilePath: ".env", IsSensitive: true}},
		Attention:         []storage.AttentionFinding{{Kind: "blocked_action", Summary: "deploy", Status: "blocked"}},
	}
	var out bytes.Buffer
	if err := renderSession(&out, session); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "[SENSITIVE] file_read · .env") || !strings.Contains(out.String(), "Blocked action · deploy · blocked") {
		t.Fatalf("unexpected session output:\n%s", out.String())
	}
}
