package cmd

import (
	"fmt"

	"github.com/secuardenai/secuarden-cli/internal/agent"
	"github.com/spf13/cobra"
)

func init() {
	hooks := &cobra.Command{Use: "hooks", Short: "Maintain installed agent hooks"}
	hooks.AddCommand(&cobra.Command{
		Use: "refresh", Short: "Refresh existing Secuarden hooks with this binary's absolute path",
		Long: "Refresh existing Secuarden hooks, preserving unrelated hooks and repository configuration. Codex may require review of changed hook commands; this command does not modify hook trust approvals.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if agent.HooksInstalled() {
				if err := agent.InstallHooks(); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Claude Code hooks refreshed.")
			}
			if agent.CodexHooksInstalled() {
				if err := agent.InstallCodexHooks(); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Codex hooks refreshed. Review changed hook commands in Codex if prompted.")
			}
			return nil
		},
	})
	rootCmd.AddCommand(hooks)
}
