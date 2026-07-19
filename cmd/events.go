package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

var (
	eventsLast      int
	eventsAction    string
	eventsSessionID string
	eventsSensitive bool
	eventsJSON      bool
)

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Show the chronological raw event log",
	Long:  "Show recent privacy-safe captured events. Filters can be combined.",
	Args:  cobra.NoArgs,
	RunE:  runEvents,
}

func init() {
	eventsCmd.Flags().IntVar(&eventsLast, "last", 20, "number of recent matching events to show")
	eventsCmd.Flags().StringVar(&eventsAction, "action", "", "filter by action type (for example command_exec)")
	eventsCmd.Flags().StringVar(&eventsSessionID, "session", "", "filter by session ID")
	eventsCmd.Flags().BoolVar(&eventsSensitive, "sensitive", false, "show only sensitive events")
	eventsCmd.Flags().BoolVar(&eventsJSON, "json", false, "emit stable JSON")
}

func runEvents(cmd *cobra.Command, args []string) error {
	if eventsLast <= 0 {
		return fmt.Errorf("--last must be greater than zero")
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
	result, err := db.QueryEvents(storage.EventFilter{
		Limit: eventsLast, ActionType: eventsAction, SessionID: eventsSessionID,
		Sensitive: eventsSensitive,
	})
	if err != nil {
		return err
	}
	if eventsJSON {
		return writeJSON(cmd.OutOrStdout(), result)
	}
	return renderEvents(cmd.OutOrStdout(), result)
}

func renderEvents(w io.Writer, result []storage.StoredEvent) error {
	if len(result) == 0 {
		fmt.Fprintln(w, "No events match the selected filters.")
		return nil
	}
	for _, event := range result {
		marker := ""
		if event.IsSensitive {
			marker = " [SENSITIVE]"
		}
		fmt.Fprintf(w, "%s  %-17s %s%s\n", event.Timestamp, event.ActionType, eventSummary(event), marker)
		if event.ResultStatus != "" || event.ExitCode != nil {
			parts := make([]string, 0, 2)
			if event.ResultStatus != "" {
				parts = append(parts, "status: "+event.ResultStatus)
			}
			if event.ExitCode != nil {
				parts = append(parts, fmt.Sprintf("exit: %d", *event.ExitCode))
			}
			fmt.Fprintf(w, "  %s\n", strings.Join(parts, " · "))
		}
	}
	return nil
}

func eventSummary(event storage.StoredEvent) string {
	if event.FilePath != "" {
		return event.FilePath
	}
	if event.Command != "" {
		return event.Command
	}
	if event.MCPServer != "" && event.MCPTool != "" {
		return event.MCPServer + "/" + event.MCPTool
	}
	if event.MCPTool != "" {
		return event.MCPTool
	}
	if event.ToolName != "" {
		return event.ToolName
	}
	return event.SessionID
}

func writeJSON(w io.Writer, value interface{}) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
