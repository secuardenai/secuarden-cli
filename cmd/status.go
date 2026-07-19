package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/agent"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/identity"
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
	CaptureActive bool
	Agent         string
	DatabasePath  string
	DatabaseSize  int64
	Sync          string
	Developer     string
	Summary       *storage.StatusSummary
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

	cfg, _ := config.Load()
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

	return renderStatus(cmd.OutOrStdout(), statusView{
		CaptureActive: agent.HooksInstalled(), Agent: summary.Agent,
		DatabasePath: dbPath, DatabaseSize: fileSize(dbPath), Sync: syncMode,
		Developer: developer, Summary: summary,
	})
}

func renderStatus(w io.Writer, view statusView) error {
	agentName := displayAgent(view.Agent)
	if agentName == "Unknown" {
		agentName = "Claude Code"
	}
	capture := "Not installed · " + agentName + " · run `secuarden init`"
	if view.CaptureActive {
		capture = "Active · " + agentName
	}
	fmt.Fprintf(w, "Secuarden Capture Agent %s\n\n", Version)
	fmt.Fprintf(w, "Capture: %s\n", capture)
	fmt.Fprintf(w, "Database: %s · %s\n", homeRelative(view.DatabasePath), formatBytes(view.DatabaseSize))
	fmt.Fprintf(w, "Sync: %s\n", view.Sync)
	fmt.Fprintf(w, "Developer: %s\n", view.Developer)

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
	if len(s.Attention) == 0 {
		fmt.Fprintln(w, "  None detected in today's captured activity.")
	} else {
		for _, finding := range s.Attention {
			fmt.Fprintf(w, "  ⚠ %-18s %s%s\n", findingLabel(finding.Kind), finding.Summary, findingSuffix(finding))
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
