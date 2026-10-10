package cmd

import (
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func TestRenderStatusIncludesScopeAndHookEventHealth(t *testing.T) {
	var out strings.Builder
	err := renderStatus(&out, statusView{
		DatabasePath:  "/tmp/secuarden.db",
		CaptureScope:  "approved",
		ApprovedRepos: []string{"/tmp/approved"},
		CurrentRepo:   "/tmp/approved",
		ClaudeHooks:   true,
		CodexHooks:    false,
		LatestEvents:  []storage.LatestAgentEvent{{AgentName: "claude-code", CapturedAt: "2026-09-22T10:00:00Z"}},
		ScopeSkips:    map[string]int{"unapproved_repository": 2},
		PrivacyMode:   "redacted_content",
		Summary:       &storage.StatusSummary{Attention: []storage.AttentionFinding{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Capture scope:", "approved repositories only",
		"Current repository:", "/tmp/approved",
		"Claude Code hooks:", "Codex hooks:", "not installed",
		"Claude Code: 2026-09-22T10:00:00Z",
		"Codex: none received",
		"Skipped unapproved repository: 2",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status output missing %q:\n%s", want, out.String())
		}
	}
}
