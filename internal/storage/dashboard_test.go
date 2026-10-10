package storage

import (
	"fmt"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/events"
)

func TestDashboardPreservesConfirmedEvidenceAndFilters(t *testing.T) {
	db, _ := tempDB(t)
	for _, agent := range []string{"codex", "claude-code"} {
		if err := db.EnsureSession(agent, agent, "/demo"); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Date(2026, 10, 10, 0, 0, 0, 0, time.FixedZone("AEST", 10*3600))
	end := start.AddDate(0, 0, 1)
	items := []events.Event{
		{ID: "attempt", HookPhase: "pre", ActionType: "file_write", FilePath: "attempt.go", Outcome: "success", ExecutionStatus: "completed"},
		{ID: "failed-write", HookPhase: "post", ActionType: "file_write", FilePath: "failed.go", ResultStatus: "error"},
		{ID: "unknown-write", HookPhase: "post", ActionType: "file_write", FilePath: "unknown.go", ResultStatus: "success"},
		{ID: "patch", HookPhase: "post", ActionType: "file_write", FilePath: "a.go", Outcome: "success", ExecutionStatus: "completed", AffectedFiles: []events.AffectedFile{{Path: "a.go"}, {Path: "b.go"}}},
		{ID: "blocked", HookPhase: "pre", ActionType: "command_exec", Command: "deploy", ResultStatus: "blocked"},
		{ID: "unknown-command", HookPhase: "post", ActionType: "command_exec", Command: "printf 'hello'", ResultStatus: "success", ExitCode: intPtr(0)},
		{ID: "passed-command", HookPhase: "post", ActionType: "command_exec", Command: "go test", Outcome: "success", ExecutionStatus: "completed"},
		{ID: "failed-command", HookPhase: "post", ActionType: "command_exec", Command: "go build", Outcome: "error", ExecutionStatus: "failed"},
		{ID: "sensitive", HookPhase: "post", ActionType: "file_read", FilePath: ".env", IsSensitive: true},
		{ID: "rejected", HookPhase: "pre", ActionType: "file_write", ResultStatus: "rejected"},
	}
	for i, e := range items {
		e.SessionID = "codex"
		e.AgentName = "codex"
		if e.ID == "sensitive" {
			e.SessionID = "claude-code"
			e.AgentName = "claude-code"
		}
		e.Source = "secuarden-cli"
		e.Timestamp = start.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		if err := db.WriteEvent(&e); err != nil {
			t.Fatal(err)
		}
	}
	// Exclusive end bound, with an event which would otherwise match the query.
	if err := db.WriteEvent(&events.Event{ID: "tomorrow", SessionID: "codex", AgentName: "codex", Source: "secuarden-cli", Timestamp: end.Format(time.RFC3339), HookPhase: "post", ActionType: "command_exec"}); err != nil {
		t.Fatal(err)
	}
	summary, err := db.GetStatusSummary(start, end, 10)
	if err != nil {
		t.Fatal(err)
	}
	d := summary.Dashboard
	if summary.Today.Actions != len(items) || summary.Today.FilesChanged != 2 || summary.Today.Commands != 3 || d.CommandPassed != 1 || d.CommandFailed != 1 || d.CommandUnknown != 1 || d.Errors != 2 || d.Blocked != 1 || d.Rejected != 1 || d.Sensitive != 1 {
		t.Fatalf("wrong summary: %+v dashboard=%+v", summary, d)
	}
	if len(d.ChangedFiles) != 2 || d.ChangedFiles[0].Label != "a.go" || d.ChangedFiles[1].Label != "b.go" || len(d.Agents) != 2 {
		t.Fatalf("incorrect chart groups: %+v", d)
	}
	if len(d.Timeline) != 24 || d.Timeline[0].Count != len(items) {
		t.Fatalf("timezone shifted events: %+v", d.Timeline)
	}
	for _, tc := range []struct {
		name   string
		filter EventFilter
		want   int
	}{
		{"confirmed changes", EventFilter{ChangesOnly: true}, 1},
		{"patch secondary path", EventFilter{ChangesOnly: true, FilePath: "b.go"}, 1},
		{"failed path excluded", EventFilter{ChangesOnly: true, FilePath: "failed.go"}, 0},
		{"unknown path excluded", EventFilter{ChangesOnly: true, FilePath: "unknown.go"}, 0},
		{"failures", EventFilter{FailuresOnly: true}, 4},
		{"observed commands", EventFilter{ActionType: "command_exec", NonPreOnly: true}, 3},
		{"agent", EventFilter{AgentName: "claude-code", Sensitive: true}, 1},
		{"quoted command", EventFilter{Command: "printf 'hello'"}, 1},
		{"literal path", EventFilter{FilePath: "' OR 1=1 --"}, 0},
		{"session restriction", EventFilter{ChangesOnly: true, RestrictSessions: true, SessionIDs: []string{"claude-code"}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.filter.Since = start
			tc.filter.Until = end
			got, err := db.QueryEvents(tc.filter)
			if err != nil || len(got) != tc.want {
				t.Fatalf("got=%+v err=%v want=%d", got, err, tc.want)
			}
		})
	}
}

func TestDashboardTimelineHandlesDaylightSaving(t *testing.T) {
	loc, err := time.LoadLocation("Australia/Melbourne")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		month      time.Month
		day, hours int
	}{{time.October, 4, 23}, {time.April, 5, 25}} {
		t.Run(fmt.Sprint(tc.month), func(t *testing.T) {
			start := time.Date(2026, tc.month, tc.day, 0, 0, 0, 0, loc)
			end := start.AddDate(0, 0, 1)
			var all []StoredEvent
			for at := start; at.Before(end); at = at.Add(time.Hour) {
				all = append(all, StoredEvent{Timestamp: at.Add(15 * time.Minute).Format(time.RFC3339), ActionType: "file_read", AgentName: "codex"})
			}
			d := buildDashboardStats(all, start, end)
			if len(d.Timeline) != tc.hours {
				t.Fatalf("hours=%d want=%d", len(d.Timeline), tc.hours)
			}
			for i, item := range d.Timeline {
				if item.Count != 1 {
					t.Fatalf("bucket %+v", item)
				}
				if i > 0 && item.Since != d.Timeline[i-1].Until {
					t.Fatal("timeline boundaries overlap or have gaps")
				}
			}
			if d.Timeline[0].Since != start.Format(time.RFC3339) || d.Timeline[len(d.Timeline)-1].Until != end.Format(time.RFC3339) {
				t.Fatal("timeline does not cover local day")
			}
		})
	}
}
