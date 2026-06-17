package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/secuardenai/secuarden-cli/internal/agent"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/identity"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/secuardenai/secuarden-cli/internal/upload"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show capture agent status and recent events",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	fmt.Printf("Secuarden Capture Agent %s\n\n", Version)

	// Hook status
	if agent.HooksInstalled() {
		fmt.Println("Status: Active")
	} else {
		fmt.Println("Status: Hooks not installed (run: secuarden init)")
	}

	// Database
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return err
	}
	fmt.Printf("Database: %s\n", dbPath)

	db, err := storage.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot open database: %v\n", err)
		return nil
	}
	defer db.Close()

	stats, err := db.GetStats(dbPath)
	if err != nil {
		return err
	}

	sizeStr := formatBytes(stats.DBSizeBytes)
	fmt.Printf("         (%s)\n", sizeStr)
	fmt.Printf("Sessions: %d | Events: %d\n", stats.TotalSessions, stats.TotalEvents)

	// Developer identity
	dev := identity.Capture()
	if dev.Name != "" || dev.Email != "" {
		fmt.Printf("Developer: %s <%s>\n", dev.Name, dev.Email)
	}

	// Sync mode
	cfg, _ := config.Load()
	if cfg != nil && cfg.SyncEnabled {
		fmt.Printf("Sync: enabled (%s)\n", cfg.APIURL)
	} else {
		fmt.Println("Sync: local only  (run: secuarden init --api-key <key> to enable)")
	}

	// Recent events
	if len(stats.RecentEvents) > 0 {
		fmt.Println("\nLast 5 events:")
		for _, e := range stats.RecentEvents {
			ts := e.Timestamp
			if len(ts) > 19 {
				ts = ts[:19]
			}
			summary := e.Summary
			if len(summary) > 60 {
				summary = summary[:60] + "..."
			}
			fmt.Printf("  %-20s  %-16s  %s\n", ts, e.ActionType, summary)
		}
	} else {
		fmt.Println("\nNo events captured yet. Run a Claude Code session to capture events.")
	}

	// Last changeset feedback (written after every session-end sync)
	printLastFeedback()

	return nil
}

func printLastFeedback() {
	sf := upload.ReadLastFeedback()
	if sf == nil {
		return
	}

	// Parse captured_at and show age
	age := ""
	if t, err := time.Parse(time.RFC3339, sf.CapturedAt); err == nil {
		d := time.Since(t).Round(time.Minute)
		switch {
		case d < time.Minute:
			age = "just now"
		case d < time.Hour:
			age = fmt.Sprintf("%dm ago", int(d.Minutes()))
		case d < 24*time.Hour:
			age = fmt.Sprintf("%dh ago", int(d.Hours()))
		default:
			age = fmt.Sprintf("%dd ago", int(d.Hours()/24))
		}
	}

	icon := map[string]string{
		"allow":            "✓",
		"warn":             "⚠",
		"require_review":   "⚑",
		"require_evidence": "⚑",
		"block":            "✗",
	}
	mark := icon[sf.Decision]
	if mark == "" {
		mark = "·"
	}

	fmt.Println()
	fmt.Println("── Last changeset evaluation " + strings.Repeat("─", 20))
	if age != "" {
		fmt.Printf("   %s  (%s)\n", sf.CapturedAt[:19], age)
	}
	fmt.Printf("   %s  %s\n", mark, sf.Summary)
	fmt.Println(strings.Repeat("─", 49))
}

func formatBytes(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%d KB", b/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
}
