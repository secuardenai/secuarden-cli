package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/agent"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/identity"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/secuardenai/secuarden-cli/internal/upload"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show capture agent status and recent events",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	fmt.Printf("Secuarden Capture Agent %s\n\n", Version)

	// Hook status
	status := ""
	if agent.HooksInstalled() {
		status = "Active"
	} else {
		status = "Hooks not installed (run: secuarden init)"
	}

	// Database
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return err
	}

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

	// Developer identity
	dev := identity.Capture()
	developer := "unknown"
	if dev.Name != "" || dev.Email != "" {
		developer = fmt.Sprintf("%s <%s>", dev.Name, dev.Email)
	}

	// Sync mode
	cfg, _ := config.Load()
	syncMode := "local only (run: secuarden init --api-key <key> to enable)"
	if cfg != nil && cfg.SyncEnabled {
		syncMode = fmt.Sprintf("enabled (%s)", cfg.APIURL)
	}

	printTable([]string{"Field", "Value"}, [][]string{
		{"Status", status},
		{"Database", dbPath},
		{"DB size", sizeStr},
		{"Sessions", fmt.Sprintf("%d", stats.TotalSessions)},
		{"Events", fmt.Sprintf("%d", stats.TotalEvents)},
		{"Developer", developer},
		{"Sync", syncMode},
	})

	// Recent events
	if len(stats.RecentEvents) > 0 {
		fmt.Println("\nLast 5 events:")
		rows := make([][]string, 0, len(stats.RecentEvents))
		for _, e := range stats.RecentEvents {
			ts := e.Timestamp
			if len(ts) > 19 {
				ts = ts[:19]
			}
			summary := e.Summary
			if len(summary) > 60 {
				summary = summary[:60] + "..."
			}
			rows = append(rows, []string{ts, e.ActionType, summary})
		}
		printTable([]string{"Timestamp", "Action", "Summary"}, rows)
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

	fmt.Println("\nLast changeset evaluation:")
	rows := [][]string{}
	if age != "" {
		rows = append(rows, []string{"Captured", fmt.Sprintf("%s (%s)", sf.CapturedAt[:19], age)})
	} else {
		rows = append(rows, []string{"Captured", sf.CapturedAt})
	}
	rows = append(rows,
		[]string{"Decision", fmt.Sprintf("%s %s", mark, sf.Decision)},
		[]string{"Risk", sf.RiskLevel},
		[]string{"Summary", sf.Summary},
	)
	printTable([]string{"Field", "Value"}, rows)
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

func printTable(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i := range headers {
			if i < len(row) && len(row[i]) > widths[i] {
				widths[i] = len(row[i])
			}
		}
	}

	printSeparator(widths)
	fmt.Print("|")
	for i, h := range headers {
		fmt.Printf(" %-*s |", widths[i], h)
	}
	fmt.Println()
	printSeparator(widths)
	for _, row := range rows {
		fmt.Print("|")
		for i := range headers {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			fmt.Printf(" %-*s |", widths[i], cell)
		}
		fmt.Println()
	}
	printSeparator(widths)
}

func printSeparator(widths []int) {
	fmt.Print("+")
	for _, w := range widths {
		fmt.Print(strings.Repeat("-", w+2))
		fmt.Print("+")
	}
	fmt.Println()
}
