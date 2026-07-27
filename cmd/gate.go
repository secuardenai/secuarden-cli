package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/risk"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

var gateSince, gateFailOn string

var gateCmd = &cobra.Command{
	Use: "gate", Short: "Fail CI when captured AI changes exceed a risk threshold",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		window, err := parseTimeWindow(gateSince)
		if err != nil {
			return err
		}
		ranks := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
		threshold, ok := ranks[strings.ToLower(gateFailOn)]
		if !ok {
			return fmt.Errorf("--fail-on must be low, medium, high, or critical")
		}
		path, err := storage.DefaultDBPath()
		if err != nil {
			return err
		}
		db, err := storage.Open(path)
		if err != nil {
			return err
		}
		defer db.Close()
		integrity, err := db.VerifyIntegrity()
		if err != nil {
			return err
		}
		if !integrity.Valid {
			return fmt.Errorf("gate blocked: audit trail integrity failed")
		}
		records, err := db.ListWriteProvenance(time.Now().Add(-window))
		if err != nil {
			return err
		}
		blocked := 0
		for _, record := range records {
			a := risk.Assess(record.FilePath, record.IsSensitive)
			if ranks[a.Level] >= threshold {
				blocked++
				fmt.Fprintf(cmd.OutOrStdout(), "✗ %s · %s · score %d", record.FilePath, a.Level, a.Score)
				if len(a.Reasons) > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), " · %s", strings.Join(a.Reasons, ", "))
				}
				fmt.Fprintln(cmd.OutOrStdout())
			}
		}
		if blocked > 0 {
			return fmt.Errorf("gate blocked %d AI-authored change(s) at or above %s risk", blocked, gateFailOn)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "✓ Provenance gate passed · %d AI-authored change(s) checked\n", len(records))
		return nil
	},
}

func init() {
	gateCmd.Flags().StringVar(&gateSince, "since", "24h", "evaluation window")
	gateCmd.Flags().StringVar(&gateFailOn, "fail-on", "high", "minimum blocking risk: low, medium, high, critical")
}
