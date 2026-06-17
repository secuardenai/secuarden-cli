package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/secuardenai/secuarden-cli/internal/agent"
)

var (
	flagPurge         bool
	flagRestoreBackup bool
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove Secuarden hooks from Claude Code",
	RunE:  runUninstall,
}

func init() {
	uninstallCmd.Flags().BoolVar(&flagPurge, "purge", false, "Also delete ~/.secuarden/ and all captured data")
	uninstallCmd.Flags().BoolVar(&flagRestoreBackup, "restore-backup", false, "Restore the most recent settings.json backup")
}

func runUninstall(cmd *cobra.Command, args []string) error {
	if flagRestoreBackup {
		return restoreBackup()
	}

	if err := agent.RemoveHooks(); err != nil {
		return fmt.Errorf("remove hooks: %w", err)
	}
	fmt.Println("✓ Secuarden hooks removed from Claude Code settings")

	if flagPurge {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir := filepath.Join(home, ".secuarden")
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("purge data: %w", err)
		}
		fmt.Printf("✓ %s deleted\n", dir)
	}

	return nil
}

func restoreBackup() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	backupDir := filepath.Join(home, ".secuarden", "backups")
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return fmt.Errorf("no backups found: %w", err)
	}

	// Find the most recent backup
	var latest string
	for _, e := range entries {
		if !e.IsDir() {
			latest = filepath.Join(backupDir, e.Name())
		}
	}
	if latest == "" {
		return fmt.Errorf("no backup files found in %s", backupDir)
	}

	data, err := os.ReadFile(latest)
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		return err
	}
	fmt.Printf("✓ Restored settings from %s\n", latest)
	return nil
}
