package cmd

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

var (
	reportSince string
	reportMD    bool
	reportJSON  bool
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate an aggregated local accountability report",
	Long:  "Aggregate authoritative local capture data over a time window (default: 24h).",
	Args:  cobra.NoArgs,
	RunE:  runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportSince, "since", "24h", "report window (for example 24h or 7d)")
	reportCmd.Flags().BoolVar(&reportMD, "md", false, "emit Markdown suitable for tickets and audit records")
	reportCmd.Flags().BoolVar(&reportJSON, "json", false, "emit stable JSON")
	reportCmd.MarkFlagsMutuallyExclusive("md", "json")
}

func runReport(cmd *cobra.Command, args []string) error {
	now := time.Now()
	duration, err := parseTimeWindow(reportSince)
	if err != nil {
		return err
	}
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return err
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	report, err := db.GetAccountabilityReport(now.Add(-duration), now)
	if err != nil {
		return err
	}
	if reportJSON {
		return writeJSON(cmd.OutOrStdout(), report)
	}
	return renderReport(cmd.OutOrStdout(), report, reportMD)
}

func parseTimeWindow(value string) (time.Duration, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if strings.HasSuffix(value, "d") {
		days, err := strconv.ParseUint(strings.TrimSuffix(value, "d"), 10, 31)
		if err != nil || days == 0 {
			return 0, fmt.Errorf("invalid --since %q: use a positive duration such as 24h or 7d", value)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("invalid --since %q: use a positive duration such as 24h or 7d", value)
	}
	return duration, nil
}

func renderReport(w io.Writer, r *storage.AccountabilityReport, markdown bool) error {
	heading := func(level int, title string) {
		if markdown {
			fmt.Fprintf(w, "%s %s\n\n", strings.Repeat("#", level), title)
		} else if level == 1 {
			fmt.Fprintf(w, "%s\n\n", title)
		} else {
			fmt.Fprintf(w, "\n%s\n", title)
		}
	}
	bullet := func(text string) {
		if markdown {
			fmt.Fprintf(w, "- %s\n", text)
		} else {
			fmt.Fprintf(w, "  %s\n", text)
		}
	}
	sectionEnd := func() {
		if markdown {
			fmt.Fprintln(w)
		}
	}

	if markdown {
		heading(1, "Secuarden Local Accountability Report")
	} else {
		const title = "Secuarden Local Accountability Report"
		border := strings.Repeat("#", len(title))
		fmt.Fprintf(w, "%s\n%s\n%s\n\n", border, title, border)
	}
	fmt.Fprintf(w, "Period: %s to %s\n", r.Since, r.Until)
	if markdown {
		fmt.Fprintln(w)
	}
	heading(2, "Overall totals")
	bullet(fmt.Sprintf("%s · %s", countNoun(r.Totals.Sessions, "session"), countNoun(r.Totals.Actions, "action")))
	bullet(fmt.Sprintf("%s read · %s changed", countNoun(r.Totals.FilesRead, "file"), countNoun(r.Totals.FilesChanged, "file")))
	bullet(fmt.Sprintf("%s · %s · %s", countNoun(r.Totals.Commands, "command"), countNoun(r.Totals.MCPCalls, "MCP call"), countNoun(r.Totals.SensitiveAccesses, "sensitive access")))
	sectionEnd()

	renderNamedSection(heading, bullet, sectionEnd, "Sessions and agent activity", r.Agents, "action", "No agent activity captured.")
	renderReportStrings(heading, bullet, sectionEnd, "Files read", r.FilesRead, "No file reads captured.")
	renderReportStrings(heading, bullet, sectionEnd, "Files changed", r.FilesChanged, "No file changes captured.")

	heading(2, "Sensitive access")
	if len(r.SensitiveAccesses) == 0 {
		bullet("No sensitive accesses captured.")
	} else {
		for _, event := range r.SensitiveAccesses {
			bullet(fmt.Sprintf("[SENSITIVE] %s · %s · session %s", event.Timestamp, eventSummary(event), event.SessionID))
		}
	}
	sectionEnd()

	heading(2, "Failed, blocked, and rejected actions")
	failures := nonSensitiveFailures(r.Attention)
	if len(failures) == 0 {
		bullet("None captured.")
	} else {
		for _, finding := range failures {
			bullet(fmt.Sprintf("%s · %s%s", findingLabel(finding.Kind), finding.Summary, findingSuffix(finding)))
		}
	}
	sectionEnd()

	heading(2, "Command execution summary")
	bullet(countNoun(r.CommandExecutions, "command execution"))
	bullet(countNoun(r.CommandFailures, "captured command failure"))
	sectionEnd()
	renderNamedSection(heading, bullet, sectionEnd, "MCP activity", r.MCPActivity, "call", "No MCP activity captured.")
	renderNamedSection(heading, bullet, sectionEnd, "Developer footprint", r.Developers, "action", "No developer identity captured in this period.")
	renderNamedSection(heading, bullet, sectionEnd, "Branch footprint", r.Branches, "action", "No branch data captured in this period.")
	return nil
}

func renderNamedSection(heading func(int, string), bullet func(string), end func(), title string, values []storage.NamedCount, noun, empty string) {
	heading(2, title)
	if len(values) == 0 {
		bullet(empty)
	} else {
		for _, value := range values {
			bullet(fmt.Sprintf("%s · %s", value.Name, countNoun(value.Count, noun)))
		}
	}
	end()
}

func renderReportStrings(heading func(int, string), bullet func(string), end func(), title string, values []string, empty string) {
	heading(2, title)
	if len(values) == 0 {
		bullet(empty)
	} else {
		for _, value := range values {
			bullet(value)
		}
	}
	end()
}
