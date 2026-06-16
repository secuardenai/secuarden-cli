package agent

import (
	"os"
	"path/filepath"
)

// IsClaudeCodeInstalled returns true if ~/.claude/settings.json exists.
func IsClaudeCodeInstalled() bool {
	path := claudeSettingsPath()
	_, err := os.Stat(path)
	return err == nil
}

func claudeSettingsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", "settings.json")
}
