package cmd

import (
	"fmt"

	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

var verifyJSON bool

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the tamper-evident local audit trail",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := storage.DefaultDBPath()
		if err != nil {
			return err
		}
		db, err := storage.Open(path)
		if err != nil {
			return err
		}
		defer db.Close()
		result, err := db.VerifyIntegrity()
		if err != nil {
			return err
		}
		if verifyJSON {
			return writeJSON(cmd.OutOrStdout(), result)
		}
		if !result.Valid {
			fmt.Fprintf(cmd.OutOrStdout(), "✗ Audit trail verification failed (%d event(s) checked)\n", result.EventsChecked)
			for _, failure := range result.Failures {
				fmt.Fprintf(cmd.OutOrStdout(), "  broken chain at %s\n", failure)
			}
			return fmt.Errorf("audit trail integrity check failed")
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✓ Audit trail verified · %d events across %d sessions", result.EventsChecked, result.SessionsChecked)
		if result.LegacyEvents > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), " · %d legacy events predate hash chaining", result.LegacyEvents)
		}
		fmt.Fprintln(cmd.OutOrStdout())
		return nil
	},
}

func init() {
	verifyCmd.Flags().BoolVar(&verifyJSON, "json", false, "emit stable JSON")
}
