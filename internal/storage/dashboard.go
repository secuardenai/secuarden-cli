package storage

import (
	"sort"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/events"
)

// Match appliedFilePaths: attempts and unknown results are not confirmed changes.
const confirmedFileChangeSQL = "(action_type IN ('file_write','file_delete') AND hook_phase='post' AND outcome='success' AND execution_status='completed')"
const dashboardFailureSQL = "(result_status IN ('error','failed','failure','blocked','rejected') OR outcome='error' OR execution_status='failed' OR (exit_code IS NOT NULL AND exit_code != 0))"

type DashboardItem struct {
	Label string `json:"label"`
	Count int    `json:"count"`
	Since string `json:"since,omitempty"`
	Until string `json:"until,omitempty"`
}

type DashboardStats struct {
	Activity       []DashboardItem `json:"activity"`
	Agents         []DashboardItem `json:"agents"`
	Timeline       []DashboardItem `json:"timeline"`
	ChangedFiles   []DashboardItem `json:"changed_files"`
	TopCommands    []DashboardItem `json:"top_commands"`
	CommandPassed  int             `json:"command_passed"`
	CommandFailed  int             `json:"command_failed"`
	CommandUnknown int             `json:"command_unknown"`
	Errors         int             `json:"errors"`
	Blocked        int             `json:"blocked"`
	Rejected       int             `json:"rejected"`
	Sensitive      int             `json:"sensitive"`
	Partial        int             `json:"partial"`
}

func dashboardItems(counts map[string]int, limit int) []DashboardItem {
	items := make([]DashboardItem, 0, len(counts))
	for label, count := range counts {
		items = append(items, DashboardItem{Label: label, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Label < items[j].Label
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func buildDashboardStats(all []StoredEvent, start, end time.Time) DashboardStats {
	d := DashboardStats{Timeline: make([]DashboardItem, 0, 24)}
	activity, agents, changed, commands := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	// Explicit boundaries keep drill-downs on the same day and timezone as the
	// summary, including 23/25-hour days and pages left open across midnight.
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		until := at.Add(time.Hour)
		if until.After(end) {
			until = end
		}
		d.Timeline = append(d.Timeline, DashboardItem{Label: at.Format("15"), Since: at.Format(time.RFC3339), Until: until.Format(time.RFC3339)})
	}
	for _, e := range all {
		activity[e.ActionType]++
		agents[e.AgentName]++
		if at, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil && !at.Before(start) && at.Before(end) {
			index := int(at.Sub(start) / time.Hour)
			if index < len(d.Timeline) {
				d.Timeline[index].Count++
			}
		}
		paths := map[string]bool{}
		for _, path := range appliedFilePaths(e) {
			paths[path] = true
		}
		for path := range paths {
			changed[path]++
		}
		if e.ActionType == events.ActionCommandExec && e.HookPhase != events.HookPhasePre {
			if e.Command != "" {
				commands[e.Command]++
			}
			switch confirmedCommandOutcome(e) {
			case events.ResultSuccess:
				d.CommandPassed++
			case events.ResultError:
				d.CommandFailed++
			default:
				d.CommandUnknown++
			}
		}
		if e.IsSensitive && e.HookPhase != events.HookPhasePre {
			d.Sensitive++
		}
		if e.Completeness.State == "partial" {
			d.Partial++
		}
		switch e.ResultStatus {
		case "blocked":
			d.Blocked++
		case "rejected":
			d.Rejected++
		default:
			if confirmedCommandOutcome(e) == events.ResultError {
				d.Errors++
			}
		}
	}
	d.Activity = dashboardItems(activity, 8)
	d.Agents = dashboardItems(agents, 8)
	d.ChangedFiles = dashboardItems(changed, 5)
	d.TopCommands = dashboardItems(commands, 5)
	return d
}
