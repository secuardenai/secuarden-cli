package cmd

import (
	"github.com/spf13/cobra"
)

// Version is set at build time via ldflags.
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "secuarden",
	Short: "Secuarden capture agent for AI coding sessions",
	Long:  "Secuarden captures governance events from AI coding agent sessions to a local SQLite database.",
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(eventsCmd)
	rootCmd.AddCommand(sessionCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(hookCmd)
}
