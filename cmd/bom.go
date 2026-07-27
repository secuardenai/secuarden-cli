package cmd

import (
	"fmt"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/risk"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/spf13/cobra"
)

var bomSince string

type aiBOM struct {
	Format      string                   `json:"format"`
	Version     string                   `json:"version"`
	GeneratedAt string                   `json:"generated_at"`
	Integrity   *storage.IntegrityResult `json:"integrity"`
	Components  []bomComponent           `json:"components"`
}
type bomComponent struct {
	storage.ProvenanceRecord
	Risk risk.Assessment `json:"risk"`
}

var bomCmd = &cobra.Command{
	Use: "bom", Short: "Export a tamper-evident AI Bill of Materials as JSON",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		window, err := parseTimeWindow(bomSince)
		if err != nil {
			return err
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
		records, err := db.ListWriteProvenance(time.Now().Add(-window))
		if err != nil {
			return err
		}
		integrity, err := db.VerifyIntegrity()
		if err != nil {
			return err
		}
		out := aiBOM{Format: "secuarden-ai-bom", Version: "1.0", GeneratedAt: time.Now().UTC().Format(time.RFC3339), Integrity: integrity, Components: []bomComponent{}}
		for _, record := range records {
			out.Components = append(out.Components, bomComponent{ProvenanceRecord: record, Risk: risk.Assess(record.FilePath, record.IsSensitive)})
		}
		if !integrity.Valid {
			return fmt.Errorf("refusing AI-BOM export: audit trail integrity failed")
		}
		return writeJSON(cmd.OutOrStdout(), out)
	},
}

func init() {
	bomCmd.Flags().StringVar(&bomSince, "since", "720h", "export window (for example 24h or 30d)")
}
