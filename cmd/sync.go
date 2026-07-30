package cmd

import (
	"fmt"

	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/secuardenai/secuarden-cli/internal/upload"
	"github.com/spf13/cobra"
)

var (
	syncSessionID string
	syncLimit     int
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Upload captured sessions pending SaaS delivery",
	Args:  cobra.NoArgs,
	RunE:  runSync,
}

func init() {
	syncCmd.Flags().StringVar(&syncSessionID, "session", "", "upload a specific session, even if previously synced")
	syncCmd.Flags().IntVar(&syncLimit, "limit", 100, "maximum pending sessions to upload")
}

func runSync(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if !cfg.SyncEnabled || cfg.APIKey == "" {
		return fmt.Errorf("SaaS sync is not enabled; run `secuarden init --api-key ...`")
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

	sessionIDs := []string{}
	if syncSessionID != "" {
		sessionIDs = append(sessionIDs, syncSessionID)
	} else {
		pending, err := db.ListPendingSyncSessions(syncLimit)
		if err != nil {
			return err
		}
		for _, item := range pending {
			sessionIDs = append(sessionIDs, item.SessionID)
		}
	}
	if len(sessionIDs) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "✓ No sessions pending SaaS sync")
		return nil
	}

	synced := 0
	for _, sessionID := range sessionIDs {
		summary, err := db.ReadSessionSummary(sessionID)
		if err != nil {
			return err
		}
		feedback, err := upload.SyncSession(cfg, summary)
		if err != nil {
			_ = db.RecordSyncFailure(sessionID, err)
			return fmt.Errorf("sync session %s: %w", sessionID, err)
		}
		if err := db.RecordSyncSuccess(sessionID, summary.EventCount); err != nil {
			return fmt.Errorf("record sync success for %s: %w", sessionID, err)
		}
		if feedback != nil {
			upload.WriteFeedback(feedback, sessionID)
		}
		synced++
		fmt.Fprintf(cmd.OutOrStdout(), "✓ Synced session %s · %d events\n", sessionID, summary.EventCount)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ SaaS sync complete · %d session(s)\n", synced)
	return nil
}
