package cmd

import (
	"database/sql"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

var sessionJSON bool

var sessionCmd = &cobra.Command{
	Use:   "session <id>",
	Short: "Investigate one captured session",
	Args:  cobra.ExactArgs(1),
	RunE:  runSession,
}

func init() {
	sessionCmd.Flags().BoolVar(&sessionJSON, "json", false, "emit stable JSON")
}

func runSession(cmd *cobra.Command, args []string) error {
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return err
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	session, err := db.GetSessionInvestigation(args[0])
	if err == sql.ErrNoRows {
		return fmt.Errorf("session %q was not found", args[0])
	}
	if err != nil {
		return err
	}
	if sessionJSON {
		return writeJSON(cmd.OutOrStdout(), session)
	}
	return renderSession(cmd.OutOrStdout(), session)
}

func renderSession(w io.Writer, s *storage.SessionInvestigation) error {
	fmt.Fprintln(w, "Secuarden Session")
	fmt.Fprintf(w, "\nSession ID: %s\n", s.SessionID)
	fmt.Fprintf(w, "Agent: %s\n", displayAgent(s.Agent))
	fmt.Fprintf(w, "Developer: %s\n", developerLabel(s.DeveloperName, s.DeveloperEmail))
	fmt.Fprintf(w, "Repository: %s\n", emptyLabel(s.Repository))
	fmt.Fprintf(w, "Branch: %s\n", emptyLabel(s.Branch))
	fmt.Fprintf(w, "Started: %s\n", s.StartedAt)
	fmt.Fprintf(w, "Ended: %s\n", emptyLabel(s.EndedAt))
	if s.DurationSeconds != nil {
		fmt.Fprintf(w, "Duration: %s\n", (time.Duration(*s.DurationSeconds) * time.Second).String())
	} else {
		fmt.Fprintln(w, "Duration: In progress or unavailable")
	}
	fmt.Fprintf(w, "Events: %d\n", s.EventCount)

	fmt.Fprintln(w, "\nActions")
	if len(s.CountsByAction) == 0 {
		fmt.Fprintln(w, "  No events captured.")
	} else {
		for _, count := range s.CountsByAction {
			fmt.Fprintf(w, "  %-20s %d\n", count.ActionType, count.Count)
		}
	}
	renderStringList(w, "Files read", s.FilesRead, "No file reads captured.")
	renderStringList(w, "Files changed", s.FilesChanged, "No file changes captured.")

	fmt.Fprintln(w, "\nCommands")
	if len(s.Commands) == 0 {
		fmt.Fprintln(w, "  No commands captured.")
	} else {
		for _, command := range s.Commands {
			outcome := command.Status
			if command.ExitCode != nil {
				outcome = fmt.Sprintf("exit %d", *command.ExitCode)
			}
			if outcome == "" {
				outcome = "outcome not captured"
			}
			fmt.Fprintf(w, "  %s · %s\n", emptyLabel(command.Command), outcome)
		}
	}

	fmt.Fprintln(w, "\nMCP tools")
	if len(s.MCPTools) == 0 {
		fmt.Fprintln(w, "  No MCP activity captured.")
	} else {
		for _, tool := range s.MCPTools {
			name := tool.Tool
			if tool.Server != "" {
				name = tool.Server + "/" + tool.Tool
			}
			fmt.Fprintf(w, "  %s%s\n", name, statusSuffix(tool.Status))
		}
	}

	fmt.Fprintln(w, "\nSensitive accesses")
	if len(s.SensitiveAccesses) == 0 {
		fmt.Fprintln(w, "  None captured.")
	} else {
		for _, event := range s.SensitiveAccesses {
			fmt.Fprintf(w, "  [SENSITIVE] %s · %s\n", event.ActionType, eventSummary(event))
		}
	}

	fmt.Fprintln(w, "\nFailed, blocked, or rejected actions")
	failures := nonSensitiveFailures(s.Attention)
	if len(failures) == 0 {
		fmt.Fprintln(w, "  None captured.")
	} else {
		for _, finding := range failures {
			fmt.Fprintf(w, "  %s · %s%s\n", findingLabel(finding.Kind), finding.Summary, findingSuffix(finding))
		}
	}
	return nil
}

func renderStringList(w io.Writer, heading string, values []string, empty string) {
	fmt.Fprintf(w, "\n%s\n", heading)
	if len(values) == 0 {
		fmt.Fprintf(w, "  %s\n", empty)
		return
	}
	for _, value := range values {
		fmt.Fprintf(w, "  %s\n", value)
	}
}

func developerLabel(name, email string) string {
	if name != "" && email != "" {
		return fmt.Sprintf("%s <%s>", name, email)
	}
	return emptyLabel(strings.TrimSpace(name + " " + email))
}

func emptyLabel(value string) string {
	if value == "" {
		return "Unavailable"
	}
	return value
}

func statusSuffix(status string) string {
	if status == "" {
		return ""
	}
	return " · " + status
}

func nonSensitiveFailures(findings []storage.AttentionFinding) []storage.AttentionFinding {
	result := make([]storage.AttentionFinding, 0)
	for _, finding := range findings {
		if finding.Kind != "sensitive_access" {
			result = append(result, finding)
		}
	}
	return result
}
