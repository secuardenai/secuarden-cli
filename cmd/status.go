package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/agent"
	"github.com/secuardenai/secuarden-cli/internal/changeledger"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/identity"
	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show capture health, today's activity, and items needing attention",
	Args:  cobra.NoArgs,
	RunE:  runStatus,
}

type statusView struct {
	CaptureActive  bool
	Agent          string
	DatabasePath   string
	DatabaseSize   int64
	Sync           string
	Developer      string
	PrivacyMode    string
	Summary        *storage.StatusSummary
	CaptureScope   string
	ApprovedRepos  []string
	CurrentRepo    string
	ClaudeHooks    bool
	CodexHooks     bool
	CodexState     string
	CodexReason    string
	LatestEvents   []storage.LatestAgentEvent
	ReceiptOutcome string
	ReceiptMode    string
	ScopeSkips     map[string]int
}

func runStatus(cmd *cobra.Command, args []string) error {
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return err
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: cannot open database: %v\n", err)
		return nil
	}
	defer db.Close()

	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	summary, err := db.GetStatusSummary(dayStart, dayStart.AddDate(0, 0, 1), 3)
	if err != nil {
		return err
	}

	cfg, cfgErr := config.Load()
	if cfgErr != nil {
		cfg = &config.Config{CaptureScope: config.CaptureScopeAll}
	}
	if cfg.CaptureScope == "" {
		cfg.CaptureScope = config.CaptureScopeAll
	}
	if resolved, _ := config.ForRepository(cfg, ""); resolved != nil {
		cfg = resolved
	}
	syncMode := "Local only"
	if cfg != nil && cfg.SyncEnabled {
		syncMode = "Enabled"
		if cfg.APIURL != "" {
			syncMode += " · " + cfg.APIURL
		}
	}
	dev := identity.Capture()
	developer := "Unknown"
	if dev.Name != "" && dev.Email != "" {
		developer = fmt.Sprintf("%s <%s>", dev.Name, dev.Email)
	} else if dev.Name != "" {
		developer = dev.Name
	} else if dev.Email != "" {
		developer = dev.Email
	}

	activeClaude := agent.HooksInstalled()
	codexInstalled := agent.CodexHooksInstalled()
	codexStatus := agent.InspectCodex()
	activeCodex := codexInstalled && codexStatus.State == agent.CodexHookEnabled
	latestEvents, err := db.LatestAgentEvents()
	if err != nil {
		return err
	}
	scopeSkips, err := db.ScopeSkipCounts()
	if err != nil {
		return err
	}
	currentRepo := ""
	if current, err := repository.ResolveCurrent(""); err == nil && current.RootValid {
		currentRepo = current.Root
	}
	receiptMode, receiptOutcome := "explicit", "No receipt capture recorded"
	if currentRepo != "" {
		if mode := cfg.RepositoryIntegrations[currentRepo].Receipt.Mode; mode != "" {
			receiptMode = mode
		}
		if path, err := changeledger.DefaultDBPath(); err == nil {
			if ledger, err := changeledger.Open(path); err == nil {
				if outcome, err := ledger.LatestReceiptOutcome(currentRepo); err == nil {
					receiptOutcome = outcome
				}
				ledger.Close()
			}
		}
	}
	statusAgent := ""
	switch {
	case activeCodex && !activeClaude:
		statusAgent = "codex"
	case activeClaude && !activeCodex:
		statusAgent = "claude-code"
	case activeClaude && activeCodex:
		statusAgent = "Claude Code + Codex"
	}
	return renderStatus(cmd.OutOrStdout(), statusView{
		CaptureActive: activeClaude || activeCodex, Agent: statusAgent,
		DatabasePath: dbPath, DatabaseSize: fileSize(dbPath), Sync: syncMode,
		Developer: developer, PrivacyMode: cfg.PrivacyMode, Summary: summary,
		CaptureScope: cfg.CaptureScope, ApprovedRepos: cfg.ApprovedRepositories,
		CurrentRepo: currentRepo, ClaudeHooks: activeClaude, CodexHooks: codexInstalled,
		CodexState: string(codexStatus.State), CodexReason: codexStatus.Reason,
		LatestEvents: latestEvents, ScopeSkips: scopeSkips,
		ReceiptMode: receiptMode, ReceiptOutcome: receiptOutcome,
	})
}

func renderStatus(w io.Writer, view statusView) error {
	agentName := displayAgent(view.Agent)
	if agentName == "Unknown" {
		agentName = "Claude Code"
	}
	capture := "Not installed · " + agentName + " · run `secuarden init`"
	if view.CaptureActive {
		capture = "Configured · " + agentName
	} else if view.CodexHooks {
		capture = "Inactive · Codex · see capability details below"
	}
	title := fmt.Sprintf("Secuarden Capture Agent %s", Version)
	border := strings.Repeat("+", len([]rune(title)))
	if colorOutput(w) {
		fmt.Fprintf(w, "%s\n\033[1;36m%s\033[0m\n%s\n\n", border, title, border)
	} else {
		fmt.Fprintf(w, "%s\n%s\n%s\n\n", border, title, border)
	}
	rows := []statusTableRow{
		{Label: "Capture:", Value: capture},
		{Label: "Database:", Value: fmt.Sprintf("%s · %s", homeRelative(view.DatabasePath), formatBytes(view.DatabaseSize))},
		{Label: "Sync:", Value: view.Sync},
		{Label: "Capture scope:", Value: formatCaptureScope(view)},
	}
	if view.ReceiptMode != "" {
		rows = append(rows, statusTableRow{Label: "Receipt mode:", Value: view.ReceiptMode}, statusTableRow{Label: "Last receipt:", Value: view.ReceiptOutcome})
	}
	if view.CurrentRepo != "" {
		rows = append(rows, statusTableRow{Label: "Current repository:", Value: homeRelative(view.CurrentRepo)})
	}
	if len(view.ApprovedRepos) > 0 {
		approved := make([]string, 0, len(view.ApprovedRepos))
		for _, repo := range view.ApprovedRepos {
			approved = append(approved, homeRelative(repo))
		}
		rows = append(rows, statusTableRow{Label: "Approved repositories:", Value: strings.Join(approved, "\n")})
	}
	rows = append(rows,
		statusTableRow{Label: "Claude Code hooks:", Value: installedLabel(view.ClaudeHooks)},
		statusTableRow{Label: "Codex hooks:", Value: installedLabel(view.CodexHooks)},
	)
	if view.CodexState != "" {
		capability := view.CodexState
		if view.CodexReason != "" {
			capability += " (" + view.CodexReason + ")"
		}
		rows = append(rows, statusTableRow{Label: "Codex capability:", Value: capability})
	}
	lastEvents := "- Claude Code: " + latestEventLabel(view.LatestEvents, "claude-code") +
		"\n- Codex: " + latestEventLabel(view.LatestEvents, "codex")
	rows = append(rows,
		statusTableRow{Label: "Last persisted event:", Value: lastEvents},
		statusTableRow{Label: "Developer:", Value: view.Developer},
	)
	privacyMode := view.PrivacyMode
	if privacyMode == "" {
		privacyMode = "redacted_content"
	}
	rows = append(rows, statusTableRow{Label: "Privacy:", Value: privacyMode})
	renderStatusTable(w, rows)

	s := view.Summary
	fmt.Fprintln(w, "\nToday")
	if s.Today.Actions == 0 {
		fmt.Fprintln(w, "  No captured activity today.")
	} else {
		fmt.Fprintf(w, "  %s · %s · %s read · %s changed\n",
			countNoun(s.Today.Sessions, "session"), countNoun(s.Today.Actions, "action"),
			countNoun(s.Today.FilesRead, "file"), countNoun(s.Today.FilesChanged, "file"))
		fmt.Fprintf(w, "  %s · %s · %s\n",
			countNoun(s.Today.Commands, "command"), countNoun(s.Today.MCPCalls, "MCP call"), countNoun(s.Today.SensitiveAccesses, "sensitive access"))
	}

	fmt.Fprintln(w, "\nNeeds attention")
	if s.CaptureFailures > 0 {
		fmt.Fprintf(w, "  ⚠ Capture health     %s could not be persisted; affected sessions are partial\n", countNoun(s.CaptureFailures, "event"))
	}
	if len(s.Attention) == 0 && s.CaptureFailures == 0 {
		fmt.Fprintln(w, "  None detected in today's captured activity.")
	} else {
		for _, finding := range s.Attention {
			fmt.Fprintf(w, "  ⚠ %-18s %s%s\n", findingLabel(finding.Kind), finding.Summary, findingSuffix(finding))
		}
	}
	if len(view.ScopeSkips) > 0 {
		fmt.Fprintln(w, "\nScope diagnostics")
		for _, reason := range []string{"missing_working_directory", "unresolvable_working_directory", "non_git_directory", "different_repository", "unapproved_repository"} {
			if count := view.ScopeSkips[reason]; count > 0 {
				fmt.Fprintf(w, "  Skipped %s: %d\n", scopeSkipLabel(reason), count)
			}
		}
	}

	fmt.Fprintln(w, "\nRecent sessions")
	if len(s.RecentSessions) == 0 {
		fmt.Fprintln(w, "  No sessions captured yet.")
	} else {
		for _, session := range s.RecentSessions {
			timeLabel := shortTime(session.StartedAt)
			changes := fmt.Sprintf("%d files changed", session.FilesChanged)
			if session.FilesChanged == 0 {
				changes = "no changes"
			}
			attention := "clean"
			if session.Completeness == "partial" {
				attention = "partial evidence"
			}
			if session.Warnings == 1 {
				attention = "1 warning"
			} else if session.Warnings > 1 {
				attention = fmt.Sprintf("%d warnings", session.Warnings)
			}
			fmt.Fprintf(w, "  %s  %-20s %d actions · %s · %s\n",
				timeLabel, session.Label, session.EventCount, changes, attention)
		}
	}

	fmt.Fprintln(w, "\nRun `secuarden events` for the raw event log.")
	fmt.Fprintln(w, "Run `secuarden report` for the full accountability report.")
	return nil
}

type statusTableRow struct {
	Label string
	Value string
}

func renderStatusTable(w io.Writer, rows []statusTableRow) {
	labelWidth, valueWidth := 0, 0
	for _, row := range rows {
		if width := len([]rune(row.Label)); width > labelWidth {
			labelWidth = width
		}
		for _, line := range strings.Split(row.Value, "\n") {
			if width := len([]rune(line)); width > valueWidth {
				valueWidth = width
			}
		}
	}
	separator := "+" + strings.Repeat("-", labelWidth+2) + "+" + strings.Repeat("-", valueWidth+2) + "+"
	fmt.Fprintln(w, separator)
	for _, row := range rows {
		lines := strings.Split(row.Value, "\n")
		for i, line := range lines {
			label := ""
			if i == 0 {
				label = row.Label
			}
			labelCell := fmt.Sprintf(" %-*s ", labelWidth, label)
			if colorOutput(w) && label != "" {
				labelCell = " \033[1;36m" + fmt.Sprintf("%-*s", labelWidth, label) + "\033[0m "
			}
			fmt.Fprintf(w, "|%s| %-*s |\n", labelCell, valueWidth, line)
		}
	}
	fmt.Fprintln(w, separator)
}

func formatCaptureScope(view statusView) string {
	switch view.CaptureScope {
	case config.CaptureScopeRepo:
		return "this repository only"
	case config.CaptureScopeApproved:
		return "approved repositories only"
	default:
		return "all supported projects for this OS user"
	}
}

func installedLabel(installed bool) string {
	if installed {
		return "installed"
	}
	return "not installed"
}

func latestEventLabel(events []storage.LatestAgentEvent, agentName string) string {
	for _, event := range events {
		if strings.EqualFold(event.AgentName, agentName) {
			return event.CapturedAt
		}
	}
	return "none received"
}

func scopeSkipLabel(reason string) string {
	switch reason {
	case "missing_working_directory":
		return "missing working directory"
	case "unresolvable_working_directory":
		return "unresolvable working directory"
	case "non_git_directory":
		return "non-Git directory"
	case "different_repository":
		return "different repository"
	case "unapproved_repository":
		return "unapproved repository"
	default:
		return "out-of-scope session"
	}
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func homeRelative(path string) string {
	home, err := os.UserHomeDir()
	if err == nil && (path == home || strings.HasPrefix(path, home+string(os.PathSeparator))) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}

func formatBytes(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%d KB", b/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
}

func displayAgent(name string) string {
	switch strings.ToLower(name) {
	case "claude-code", "claude code":
		return "Claude Code"
	case "codex":
		return "Codex"
	case "":
		return "Unknown"
	default:
		return name
	}
}

func shortTime(value string) string {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return t.Local().Format("15:04")
}

func findingLabel(kind string) string {
	switch kind {
	case "sensitive_access":
		return "Sensitive access"
	case "failed_command":
		return "Failed command"
	case "blocked_action":
		return "Blocked action"
	case "rejected_action":
		return "Rejected action"
	case "failed_action":
		return "Failed action"
	default:
		return "Captured warning"
	}
}

func findingSuffix(f storage.AttentionFinding) string {
	if f.Kind == "failed_command" && f.ExitCode != nil {
		return fmt.Sprintf(" · exit %d", *f.ExitCode)
	}
	if (f.Kind == "blocked_action" || f.Kind == "rejected_action") && f.Status != "" {
		return " · " + f.Status
	}
	return ""
}

func countNoun(count int, noun string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, noun)
	}
	suffix := "s"
	if strings.HasSuffix(noun, "access") {
		suffix = "es"
	}
	return fmt.Sprintf("%d %s%s", count, noun, suffix)
}
