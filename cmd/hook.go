package cmd

import (
	"github.com/spf13/cobra"
	"github.com/secuardenai/secuarden-cli/internal/capture"
)

// hookCmd is hidden from --help; it's invoked by Claude Code hooks only.
var hookCmd = &cobra.Command{
	Use:    "hook",
	Short:  "Internal: process a Claude Code hook event from stdin",
	Hidden: true,
}

var preToolUseCmd = &cobra.Command{
	Use:    "pre-tool-use",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		capture.HandleHookEvent("pre-tool-use", Version)
	},
}

var postToolUseCmd = &cobra.Command{
	Use:    "post-tool-use",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		capture.HandleHookEvent("post-tool-use", Version)
	},
}

var sessionStartCmd = &cobra.Command{
	Use:    "session-start",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		capture.HandleHookEvent("session-start", Version)
	},
}

var sessionEndCmd = &cobra.Command{
	Use:    "session-end",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		capture.HandleHookEvent("session-end", Version)
	},
}

func init() {
	hookCmd.AddCommand(preToolUseCmd)
	hookCmd.AddCommand(postToolUseCmd)
	hookCmd.AddCommand(sessionStartCmd)
	hookCmd.AddCommand(sessionEndCmd)
}
