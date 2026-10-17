package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/secuardenai/secuarden-cli/internal/storage"
)

// The summary has a conservative fallback because terminal width is not
// available when stdout is redirected. COLUMNS lets callers choose a width.
func sessionSummaryWidth() int {
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n >= 50 {
		return min(n, 120)
	}
	return 76
}

func formatSessionDuration(seconds int64) string {
	return (time.Duration(seconds) * time.Second).String()
}

func renderSessionSummary(w io.Writer, s *storage.SessionInvestigation) error {
	width := sessionSummaryWidth()
	sessionSection(w, "SESSION", width, false)
	sessionField(w, "ID", s.SessionID, width)
	sessionField(w, "Agent", displayAgent(s.Agent), width)
	sessionField(w, "Developer", developerLabel(s.DeveloperName, s.DeveloperEmail), width)
	sessionField(w, "Repository", emptyLabel(s.Repository), width)
	sessionField(w, "Branch", emptyLabel(s.Branch), width)
	sessionField(w, "Started", emptyLabel(s.StartedAt), width)
	end := s.EndedAt
	if end == "" {
		end = "Not captured"
	}
	sessionField(w, "Ended", end, width)
	if s.DurationSeconds != nil {
		sessionField(w, "Duration", formatSessionDuration(*s.DurationSeconds), width)
	}

	sessionField(w, "Baseline", emptyLabel(s.BaselineStatus), width)
	sessionField(w, "Checkpoint", emptyLabel(s.EndCheckpointStatus), width)
	sessionSection(w, "ACTIVITY", width, true)
	fmt.Fprintf(w, "  %-22s %6s\n", "Action type", "Events")
	fmt.Fprintf(w, "  %-22s %6d\n", "Total", s.EventCount)
	counts := make(map[string]int, len(s.CountsByAction))
	for _, action := range s.CountsByAction {
		counts[action.ActionType] = action.Count
		fmt.Fprintf(w, "  %-22s %6d\n", action.ActionType, action.Count)
	}
	fmt.Fprintln(w)
	sessionField(w, "Paths", fmt.Sprintf("%d changed, %d read", len(s.FilesChanged), len(s.FilesRead)), width)
	if writes := counts["file_write"] + counts["file_delete"]; writes > 0 && len(s.FilesChanged) == 0 {
		sessionField(w, "Gap", fmt.Sprintf("%d write events have no confirmed file changes", writes), width)
	}
	if reads := counts["file_read"]; reads > 0 && len(s.FilesRead) == 0 {
		sessionField(w, "Gap", fmt.Sprintf("%d read events have no captured file paths", reads), width)
	}
	if s.EndedAt == "" {
		sessionField(w, "Note", "End not captured; the session may still be active or its ending was missed.", width)
	}

	sessionSection(w, "CAPTURED INTENT", width, true)
	if len(s.Intents) == 0 {
		sessionText(w, "  ", "No intent text captured.", width, 0)
	} else {
		start := max(0, len(s.Intents)-3)
		for i, intent := range s.Intents[start:] {
			sessionText(w, fmt.Sprintf("  %d. ", start+i+1), intent, width, 160)
		}
		if start > 0 {
			fmt.Fprintf(w, "  +%d earlier intent records\n", start)
		}
	}

	sessionSection(w, "FILES CHANGED", width, true)
	if len(s.FilesChanged) == 0 {
		sessionText(w, "  ", "No changed file paths captured.", width, 0)
	} else {
		for _, path := range s.FilesChanged[:min(len(s.FilesChanged), 12)] {
			sessionText(w, "  ", path, width, 0)
		}
		if len(s.FilesChanged) > 12 {
			fmt.Fprintf(w, "  +%d more changed paths\n", len(s.FilesChanged)-12)
		}
	}

	sessionSection(w, "ATTENTION", width, true)
	failures := nonSensitiveFailures(s.Attention)
	if len(s.SensitiveAccesses) == 0 && len(failures) == 0 {
		sessionText(w, "  ", "No sensitive access or failed, blocked, or rejected action captured.", width, 0)
	}
	for _, event := range s.SensitiveAccesses[:min(len(s.SensitiveAccesses), 5)] {
		sessionText(w, "  ", "[SENSITIVE] "+event.ActionType+" · "+eventSummary(event), width, 140)
	}
	if len(s.SensitiveAccesses) > 5 {
		fmt.Fprintf(w, "  +%d more sensitive accesses\n", len(s.SensitiveAccesses)-5)
	}
	for _, finding := range failures[:min(len(failures), 5)] {
		sessionText(w, "  ", findingLabel(finding.Kind)+" · "+finding.Summary+findingSuffix(finding), width, 140)
	}
	if len(failures) > 5 {
		fmt.Fprintf(w, "  +%d more failed, blocked, or rejected actions\n", len(failures)-5)
	}

	sessionSection(w, "RECENT COMMANDS", width, true)
	if len(s.Commands) == 0 {
		sessionText(w, "  ", "No completed commands captured.", width, 0)
	} else {
		start := max(0, len(s.Commands)-4)
		for i, command := range s.Commands[start:] {
			status := command.Status
			if command.ExitCode != nil {
				status = fmt.Sprintf("exit %d", *command.ExitCode)
			}
			if status == "" {
				status = "outcome unknown"
			}
			fmt.Fprintf(w, "  %d. %s\n", start+i+1, status)
			sessionText(w, "     ", command.Command, width, 110)
		}
		if start > 0 {
			fmt.Fprintf(w, "  +%d earlier commands\n", start)
		}
	}

	if len(s.MCPTools) > 0 {
		sessionSection(w, "MCP TOOLS", width, true)
		type toolCount struct {
			name  string
			count int
		}
		byName := make(map[string]int)
		for _, tool := range s.MCPTools {
			name := tool.Tool
			if tool.Server != "" {
				name = tool.Server + "/" + name
			}
			byName[name]++
		}
		tools := make([]toolCount, 0, len(byName))
		for name, count := range byName {
			tools = append(tools, toolCount{name, count})
		}
		sort.Slice(tools, func(i, j int) bool {
			if tools[i].count != tools[j].count {
				return tools[i].count > tools[j].count
			}
			return tools[i].name < tools[j].name
		})
		for _, tool := range tools[:min(len(tools), 5)] {
			sessionText(w, fmt.Sprintf("  %3d  ", tool.count), tool.name, width, 100)
		}
		if len(tools) > 5 {
			fmt.Fprintf(w, "  +%d other tool names\n", len(tools)-5)
		}
	}

	sessionSection(w, "MORE", width, true)
	sessionText(w, "  Full:     ", "secuarden session "+s.SessionID+" --full", width, 0)
	sessionText(w, "  Timeline: ", "secuarden events --session "+s.SessionID+" --last 50", width, 0)
	return nil
}

func sessionSection(w io.Writer, title string, width int, blank bool) {
	if blank {
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, strings.Repeat("─", width))
}

func sessionField(w io.Writer, label, value string, width int) {
	sessionText(w, fmt.Sprintf("  %-12s", label), value, width, 0)
}

func sessionText(w io.Writer, prefix, value string, width, maxRunes int) {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		value = "Details unavailable"
	}
	if maxRunes > 1 && utf8.RuneCountInString(value) > maxRunes {
		runes := []rune(value)
		value = string(runes[:maxRunes-1]) + "…"
	}
	indent := strings.Repeat(" ", utf8.RuneCountInString(prefix))
	available := max(12, width-utf8.RuneCountInString(prefix))
	first := true
	for len(value) > 0 {
		line := []rune(value)
		if len(line) <= available {
			if first {
				fmt.Fprint(w, prefix)
			} else {
				fmt.Fprint(w, indent)
			}
			fmt.Fprintln(w, value)
			return
		}
		cut := available
		for cut > available/2 && line[cut] != ' ' {
			cut--
		}
		if cut <= available/2 {
			cut = available
		}
		if first {
			fmt.Fprint(w, prefix)
		} else {
			fmt.Fprint(w, indent)
		}
		fmt.Fprintln(w, string(line[:cut]))
		value = strings.TrimLeft(string(line[cut:]), " ")
		first = false
	}
}
