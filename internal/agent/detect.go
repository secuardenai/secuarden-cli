package agent

import (
	"os"
	"path/filepath"
	"strings"
)

type Detection struct {
	Found  bool
	Source string
	Path   string
}

// DetectClaudeCode detects either the shared Claude settings boundary or the
// official VS Code extension. The extension bundles its own CLI, so a shell
// `claude` executable is intentionally not required here.
func DetectClaudeCode() Detection {
	if path := claudeSettingsPath(); path != "" {
		if _, err := os.Stat(path); err == nil {
			return Detection{Found: true, Source: "shared Claude settings", Path: path}
		}
	}
	if extension := detectVSCodeExtension("anthropic.claude-code"); extension.Found {
		return extension
	}
	return Detection{}
}

// DetectCodexVSCode detects the official Codex VS Code extension. This is
// detection only; hook capability still requires the Codex runtime contract.
func DetectCodexVSCode() Detection {
	return detectVSCodeExtension("openai.chatgpt")
}

// IsClaudeCodeInstalled returns true if Claude settings or its VS Code
// extension are present.
func IsClaudeCodeInstalled() bool {
	return DetectClaudeCode().Found
}

func detectVSCodeExtension(prefix string) Detection {
	home, err := os.UserHomeDir()
	if err != nil {
		return Detection{}
	}
	roots := []string{
		filepath.Join(home, ".vscode", "extensions"),
		filepath.Join(home, ".vscode-insiders", "extensions"),
	}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() && (entry.Name() == prefix || strings.HasPrefix(entry.Name(), prefix+"-")) {
				return Detection{Found: true, Source: "VS Code extension", Path: filepath.Join(root, entry.Name())}
			}
		}
	}
	return Detection{}
}

func claudeSettingsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude", "settings.json")
}
