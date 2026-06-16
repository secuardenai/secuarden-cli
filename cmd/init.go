package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/secuarden/secuarden-cli/internal/agent"
	"github.com/secuarden/secuarden-cli/internal/config"
	"github.com/secuarden/secuarden-cli/internal/identity"
	"github.com/secuarden/secuarden-cli/internal/storage"
)

var (
	initSyncAPIKey string
	initSyncAPIURL string
)

func init() {
	initCmd.Flags().StringVar(&initSyncAPIKey, "api-key", "", "Secuarden API key — enables SaaS sync and developer feedback")
	initCmd.Flags().StringVar(&initSyncAPIURL, "api-url", "", "Override Secuarden API URL (default: https://app.secuarden.ai)")
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Install Secuarden hooks and create the local database",
	Long: `Install Secuarden hooks into Claude Code and create the local SQLite database.

By default all data stays local. Pass --api-key to enable SaaS sync: at the
end of every Claude Code session the session summary is posted to Secuarden
and a risk evaluation is printed in the terminal before Claude Code exits.

  secuarden init                          # local only
  secuarden init --api-key sec_xxxx       # local + SaaS sync`,
	RunE: runInit,
}

func runInit(cmd *cobra.Command, args []string) error {
	// 1. Detect Claude Code
	if !agent.IsClaudeCodeInstalled() {
		fmt.Fprintln(os.Stderr, "✗ No supported AI coding agent detected.")
		fmt.Fprintln(os.Stderr, "  Secuarden currently supports Claude Code.")
		fmt.Fprintln(os.Stderr, "  Ensure Claude Code is installed and has been run at least once.")
		os.Exit(1)
	}
	fmt.Println("✓ Claude Code detected")

	// 2. Save config (must happen before InstallHooks so the hook binary can read it)
	syncEnabled := strings.TrimSpace(initSyncAPIKey) != ""
	cfg := &config.Config{
		SyncEnabled: syncEnabled,
		APIKey:      strings.TrimSpace(initSyncAPIKey),
		APIURL:      strings.TrimSpace(initSyncAPIURL),
	}
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	if syncEnabled {
		fmt.Println("✓ SaaS sync enabled — session feedback will appear in terminal")
	} else {
		fmt.Println("✓ Local-only mode (pass --api-key to enable SaaS sync)")
	}

	// 3. Back up and merge hooks
	if err := agent.InstallHooks(); err != nil {
		return fmt.Errorf("install hooks: %w", err)
	}
	fmt.Println("✓ Hooks installed (PreToolUse, PostToolUse, SessionStart, SessionEnd)")

	// 4. Create database
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return fmt.Errorf("db path: %w", err)
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		return fmt.Errorf("create database: %w", err)
	}
	db.Close()
	fmt.Printf("✓ Database created at %s\n", dbPath)

	// 5. Capture developer identity
	dev := identity.Capture()
	if dev.Email != "" || dev.Name != "" {
		name := dev.Name
		if name == "" {
			name = dev.OSUser
		}
		fmt.Printf("✓ Developer identity: %s <%s>\n", name, dev.Email)
	}

	fmt.Println()
	fmt.Println("Secuarden is ready. After your next Claude Code session, run:")
	fmt.Println("  secuarden status")
	return nil
}
