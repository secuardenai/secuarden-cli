package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/events"
	"github.com/secuardenai/secuarden-cli/internal/repository"
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
		Agents:    []storage.NamedCount{{Name: "claude-code", Count: 4, Sessions: 1}},
		FilesRead: []string{"README.md"}, FilesChanged: []string{},
		SensitiveAccesses: []storage.StoredEvent{}, Attention: []storage.AttentionFinding{},
		MCPActivity: []storage.NamedCount{}, Developers: []storage.NamedCount{}, Branches: []storage.NamedCount{},
	}
	var out bytes.Buffer
	if err := renderReport(&out, report, true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Secuarden accountability report", "## Summary", "## Agent activity", "- README.md", "- No sensitive-path access"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("Markdown report missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "## Sensitive-path access") || strings.Contains(out.String(), "## MCP activity") {
		t.Fatalf("empty finding sections should be omitted:\n%s", out.String())
	}
}

func TestTerminalReportCompactHeading(t *testing.T) {
	report := &storage.AccountabilityReport{
		Since: "2026-07-18T00:00:00Z", Until: "2026-07-19T00:00:00Z",
		Agents: []storage.NamedCount{}, FilesRead: []string{}, FilesChanged: []string{},
		SensitiveAccesses: []storage.StoredEvent{}, Attention: []storage.AttentionFinding{},
		MCPActivity: []storage.NamedCount{}, Developers: []storage.NamedCount{}, Branches: []storage.NamedCount{},
	}
	var out bytes.Buffer
	if err := renderReportWithOptions(&out, report, false, 10, time.UTC); err != nil {
		t.Fatal(err)
	}
	want := "Secuarden accountability report\nPeriod: Last 24 hours · 18 Jul 00:00 – 19 Jul 00:00 UTC"
	if !strings.HasPrefix(out.String(), want) {
		t.Fatalf("terminal report heading mismatch:\n%s", out.String())
	}
	if strings.Contains(out.String(), "###") {
		t.Fatalf("terminal report still contains hash banner:\n%s", out.String())
	}
}

func TestValidateReportOptions(t *testing.T) {
	if err := validateReportOptions("github.com/acme/repo", true, 10); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual exclusion error, got %v", err)
	}
	if err := validateReportOptions("", false, 0); err == nil || !strings.Contains(err.Error(), "greater than zero") {
		t.Fatalf("expected limit error, got %v", err)
	}
	if err := validateReportOptions("", true, 1); err != nil {
		t.Fatalf("valid options: %v", err)
	}
}

func TestSelectReportRepositoriesDefaultAndNoGitError(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })

	nonRepo := t.TempDir()
	if err := os.Chdir(nonRepo); err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectReportRepositories("", false, nil); err == nil || !strings.Contains(err.Error(), "--repo or --all-repos") {
		t.Fatalf("expected actionable no-Git error, got %v", err)
	}

	repoRoot := filepath.Join(t.TempDir(), "selected")
	if output, err := exec.Command("git", "init", "--quiet", repoRoot).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if output, err := exec.Command("git", "-C", repoRoot, "remote", "add", "origin", "git@github.com:acme/selected.git").CombinedOutput(); err != nil {
		t.Fatalf("git remote: %v: %s", err, output)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatal(err)
	}
	groups := []repository.Group{{Identity: repository.Identity{Canonical: "github.com/acme/selected", Name: "selected"}, SessionIDs: []string{"s1"}}}
	selected, matched, err := selectReportRepositories("", false, groups)
	if err != nil || selected.Canonical != "github.com/acme/selected" || len(matched) != 1 {
		t.Fatalf("default selection = %#v, %#v, %v", selected, matched, err)
	}
	selected, matched, err = selectReportRepositories(repoRoot, false, groups)
	if err != nil || selected.Canonical != "github.com/acme/selected" || len(matched) != 1 {
		t.Fatalf("explicit path selection = %#v, %#v, %v", selected, matched, err)
	}
	selected, matched, err = selectReportRepositories("acme/selected", false, groups)
	if err != nil || selected.Canonical != "github.com/acme/selected" || len(matched) != 1 {
		t.Fatalf("explicit identity selection = %#v, %#v, %v", selected, matched, err)
	}
	selected, matched, err = selectReportRepositories("", true, groups)
	if err != nil || selected.Canonical != "all" || len(matched) != 1 {
		t.Fatalf("all-repositories selection = %#v, %#v, %v", selected, matched, err)
	}
}

func TestCollectScopedReportAndJSONPathCompatibility(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "activity.db")
	db, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repoA, repoB := filepath.Join(t.TempDir(), "repo-a"), filepath.Join(t.TempDir(), "repo-b")
	for _, session := range []struct {
		id, root, remote, path string
	}{
		{"session-a", repoA, "https://github.com/acme/repo-a.git", filepath.Join(repoA, "src", "a.go")},
		{"session-b", repoB, "git@github.com:acme/repo-b.git", filepath.Join(repoB, "src", "b.go")},
	} {
		if err := db.EnsureSession(session.id, "claude-code", session.root); err != nil {
			t.Fatal(err)
		}
		if err := db.UpdateSessionIdentity(session.id, storage.SessionIdentity{GitRepoURL: session.remote, GitBranch: "main"}); err != nil {
			t.Fatal(err)
		}
		event := &events.Event{
			ID: "event-" + session.id, SessionID: session.id, Sequence: 1,
			Timestamp: "2026-07-19T08:00:00Z", Source: "secuarden-cli",
			AgentName: "claude-code", HookPhase: "post", ActionType: "file_read",
			FilePath: session.path, WorkingDirectory: session.root, DeveloperEmail: "dev@example.com", GitBranch: "main",
		}
		if err := db.WriteEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	externalChange := repoA + "-old/generated.go"
	for i, path := range []string{filepath.Join(repoA, "src", "changed.go"), externalChange, externalChange} {
		event := &events.Event{
			ID: fmt.Sprintf("event-change-%d", i), SessionID: "session-a", Sequence: i + 2,
			Timestamp: fmt.Sprintf("2026-07-19T08:0%d:00Z", i+1), Source: "secuarden-cli",
			AgentName: "claude-code", HookPhase: "post", ActionType: "file_write",
			FilePath: path, WorkingDirectory: repoA, DeveloperEmail: "dev@example.com", GitBranch: "main",
		}
		if err := db.WriteEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	externalRead := repoA + "-old/settings.json"
	if err := db.WriteEvent(&events.Event{
		ID: "event-external-read", SessionID: "session-a", Sequence: 5,
		Timestamp: "2026-07-19T08:05:00Z", Source: "secuarden-cli",
		AgentName: "claude-code", HookPhase: "post", ActionType: "file_read",
		FilePath: externalRead, WorkingDirectory: repoA, DeveloperEmail: "dev@example.com", GitBranch: "main",
	}); err != nil {
		t.Fatal(err)
	}
	groups := []repository.Group{
		{Identity: repository.Identity{Canonical: "github.com/acme/repo-a", Name: "repo-a", Root: repoA, RootValid: true}, SessionIDs: []string{"session-a"}},
		{Identity: repository.Identity{Canonical: "github.com/acme/repo-b", Name: "repo-b", Root: repoB, RootValid: true}, SessionIDs: []string{"session-b"}},
	}
	since := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	single, err := collectScopedReport(db, since, since.Add(24*time.Hour), groups[0].Identity, groups[:1], false, false)
	if err != nil {
		t.Fatal(err)
	}
	if single.Totals.Actions != 5 || len(single.FilesRead) != 2 {
		t.Fatalf("single repository leaked unrelated data: %#v", single)
	}
	if len(single.FileEntries) != 4 || single.Totals.RepositoryFilesRead != 1 || single.Totals.ExternalFilesRead != 1 || single.Totals.RepositoryFilesChanged != 1 || single.Totals.ExternalFilesChanged != 1 {
		t.Fatalf("path metadata = %#v", single.FileEntries)
	}
	if !containsReportPath(single.FileEntries, "src/a.go", false, "read") || !containsReportPath(single.FileEntries, externalRead, true, "read") || !containsReportPath(single.FileEntries, "src/changed.go", false, "changed") || !containsReportPath(single.FileEntries, externalChange, true, "changed") {
		t.Fatalf("incorrect path classification: %#v", single.FileEntries)
	}
	if len(single.RepositoryFilesChanged) != 1 || len(single.ExternalFilesChanged) != 1 {
		t.Fatalf("classified JSON collections were not independently deduplicated: %#v", single)
	}
	var terminal bytes.Buffer
	if err := renderReportWithOptions(&terminal, single, false, 10, time.UTC); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(terminal.String(), "1 repository file changed · 1 external file changed") ||
		!strings.Contains(terminal.String(), "Files changed\n  src/changed.go") ||
		!strings.Contains(terminal.String(), "External activity") ||
		strings.Contains(terminal.String(), "Files changed\n  "+externalChange) {
		t.Fatalf("external write appeared as a repository change:\n%s", terminal.String())
	}
	encoded, err := json.Marshal(single)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"files_read"`)) || !bytes.Contains(encoded, []byte(filepath.Join(repoA, "src", "a.go"))) ||
		!bytes.Contains(encoded, []byte(`"display_path":"src/a.go"`)) || !bytes.Contains(encoded, []byte(`"external_files_changed"`)) ||
		bytes.Contains(encoded, []byte(filepath.Join(repoB, "lib", "b.go"))) {
		t.Fatalf("JSON did not preserve original and additive display paths: %s", encoded)
	}

	all, err := collectScopedReport(db, since, since.Add(24*time.Hour), repository.Identity{Canonical: "all"}, groups, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if all.Totals.Actions != 6 || len(all.RepositoryGroups) != 2 {
		t.Fatalf("all repository grouping = %#v", all)
	}
	if !containsReportPath(all.RepositoryGroups[0].FileEntries, "repo-a/src/a.go", false, "read") || !containsReportPath(all.RepositoryGroups[1].FileEntries, "repo-b/src/b.go", false, "read") {
		t.Fatalf("per-repository paths = %#v", all.RepositoryGroups)
	}
	empty, err := collectScopedReport(db, since, since.Add(24*time.Hour), repository.Identity{Canonical: "github.com/acme/empty"}, nil, false, false)
	if err != nil || empty.Totals.Actions != 0 || empty.Repository != "github.com/acme/empty" {
		t.Fatalf("selected empty repository = %#v, %v", empty, err)
	}
}

func containsReportPath(entries []storage.ReportPath, display string, external bool, kind string) bool {
	for _, entry := range entries {
		if entry.DisplayPath == display && entry.External == external && entry.Kind == kind {
			return true
		}
	}
	return false
}

func TestTerminalLimitDoesNotMutateReportData(t *testing.T) {
	report := &storage.AccountabilityReport{
		Since: "2026-07-18T00:00:00Z", Until: "2026-07-19T00:00:00Z", Repository: "github.com/acme/repo",
		Totals: storage.ActivityCounts{Actions: 3, FilesRead: 3},
		Agents: []storage.NamedCount{}, FilesRead: []string{"a.go", "b.go", "c.go"}, FilesChanged: []string{},
		FileEntries: []storage.ReportPath{
			{FilePath: "a.go", DisplayPath: "a.go", Kind: "read"},
			{FilePath: "b.go", DisplayPath: "b.go", Kind: "read"},
			{FilePath: "c.go", DisplayPath: "c.go", Kind: "read"},
		},
		SensitiveAccesses: []storage.StoredEvent{}, Attention: []storage.AttentionFinding{},
		MCPActivity: []storage.NamedCount{}, Developers: []storage.NamedCount{}, Branches: []storage.NamedCount{},
	}
	var out bytes.Buffer
	if err := renderReportWithLimit(&out, report, false, 2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "… 1 more") || strings.Contains(out.String(), "  c.go\n") {
		t.Fatalf("terminal limit output:\n%s", out.String())
	}
	if len(report.FilesRead) != 3 || len(report.FileEntries) != 3 {
		t.Fatal("terminal rendering mutated complete report data")
	}
	out.Reset()
	if err := renderReportWithLimit(&out, report, true, 1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "- c.go") || strings.Contains(out.String(), "… 2 more") {
		t.Fatalf("Markdown should retain complete paths regardless of terminal limit:\n%s", out.String())
	}
}

func TestDecorateReportPathsResolvesCapturedRelativePath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	workingDir := filepath.Join(root, "nested")
	report := &storage.AccountabilityReport{
		FilesRead:    []string{"src/api.go"},
		PathEvidence: []storage.ReportPathEvidence{{FilePath: "src/api.go", WorkingDirectory: workingDir, Kind: "read"}},
	}
	repo := repository.Identity{
		Canonical: "github.com/acme/repo", Name: "repo", Root: root,
		RootValid: true, Roots: []string{root},
	}
	decorateReportPaths(report, repo, t.TempDir(), false, false)
	if len(report.FileEntries) != 1 || report.FileEntries[0].DisplayPath != "nested/src/api.go" || report.FileEntries[0].FilePath != "src/api.go" {
		t.Fatalf("relative captured path metadata = %#v", report.FileEntries)
	}
	decorateReportPaths(report, repo, t.TempDir(), true, false)
	if report.FileEntries[0].DisplayPath != filepath.Join(workingDir, "src", "api.go") {
		t.Fatalf("absolute display path = %#v", report.FileEntries[0])
	}
}

func TestUnresolvedRelativePathIsExternal(t *testing.T) {
	report := &storage.AccountabilityReport{
		FilesChanged: []string{"generated/output.go"},
		PathEvidence: []storage.ReportPathEvidence{{FilePath: "generated/output.go", Kind: "changed"}},
	}
	repo := repository.Identity{Canonical: "github.com/acme/repo", Name: "repo", Root: t.TempDir(), RootValid: true}
	decorateReportPaths(report, repo, t.TempDir(), false, false)
	if report.Totals.RepositoryFilesChanged != 0 || report.Totals.ExternalFilesChanged != 1 || !report.FileEntries[0].External {
		t.Fatalf("unresolved relative path was treated as repository-local: %#v", report)
	}
}

func TestAbsolutePathsPreserveClassification(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	internal := filepath.Join(root, "src", "internal.go")
	external := filepath.Join(filepath.Dir(root), "repo-old", "external.go")
	report := &storage.AccountabilityReport{
		FilesChanged: []string{internal, external},
		PathEvidence: []storage.ReportPathEvidence{
			{FilePath: internal, WorkingDirectory: root, Kind: "changed"},
			{FilePath: external, WorkingDirectory: root, Kind: "changed"},
		},
	}
	repo := repository.Identity{Canonical: "github.com/acme/repo", Name: "repo", Root: root, RootValid: true, Roots: []string{root}}
	decorateReportPaths(report, repo, t.TempDir(), true, false)
	if report.Totals.RepositoryFilesChanged != 1 || report.Totals.ExternalFilesChanged != 1 {
		t.Fatalf("absolute display changed classification: %#v", report.Totals)
	}
	if !containsReportPath(report.FileEntries, internal, false, "changed") || !containsReportPath(report.FileEntries, external, true, "changed") {
		t.Fatalf("absolute display paths = %#v", report.FileEntries)
	}
}

func TestFriendlyReportPeriodAndRepositoryDisplay(t *testing.T) {
	location := time.FixedZone("AEST", 10*60*60)
	got := friendlyReportPeriod("2026-07-18T03:52:00Z", "2026-07-19T03:52:00Z", location)
	if got != "Last 24 hours · 18 Jul 13:52 – 19 Jul 13:52 AEST" {
		t.Fatalf("friendly period = %q", got)
	}
	got = friendlyReportPeriod("2026-07-12T03:52:00Z", "2026-07-19T03:52:00Z", location)
	if !strings.HasPrefix(got, "Last 7 days · ") {
		t.Fatalf("seven-day period = %q", got)
	}
	got = friendlyReportPeriod("2026-07-19T02:52:00Z", "2026-07-19T03:52:00Z", location)
	if !strings.HasPrefix(got, "Last 1 hour · ") {
		t.Fatalf("one-hour period = %q", got)
	}
	if displayRepositoryIdentity("github.com/secuardenai/secuarden-cli") != "secuardenai/secuarden-cli" {
		t.Fatal("repository display did not remove the safely derived host")
	}
}

func TestFindingSectionsAndSensitiveTerminology(t *testing.T) {
	report := &storage.AccountabilityReport{
		Since: "2026-07-18T00:00:00Z", Until: "2026-07-19T00:00:00Z", Repository: "github.com/acme/repo",
		Totals:            storage.ActivityCounts{Sessions: 1, Actions: 2, SensitiveAccesses: 1},
		Agents:            []storage.NamedCount{{Name: "claude-code", Count: 2, Sessions: 1}},
		SensitiveAccesses: []storage.StoredEvent{{SessionID: "full-session-id", Timestamp: "2026-07-18T01:02:03.123456Z", FilePath: ".env", IsSensitive: true}},
		Attention:         []storage.AttentionFinding{{Kind: "failed_action", Summary: "tool", Status: "error"}},
		MCPActivity:       []storage.NamedCount{{Name: "memory/read", Count: 1}},
		FilesRead:         []string{}, FilesChanged: []string{}, Developers: []storage.NamedCount{}, Branches: []storage.NamedCount{},
	}
	var out bytes.Buffer
	if err := renderReportWithOptions(&out, report, false, 10, time.UTC); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Sensitive-path access", "[SENSITIVE]", "Failed, blocked, and rejected actions", "MCP activity"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("finding report missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "Secret-bearing") {
		t.Fatalf("report made unsupported secret-bearing claim:\n%s", out.String())
	}
	if strings.Contains(out.String(), "2026-07-18T") || strings.Contains(out.String(), ".123456") {
		t.Fatalf("terminal report exposed raw or nanosecond timestamps:\n%s", out.String())
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
