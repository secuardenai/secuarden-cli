package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectClaudeCodeVSCodeExtension(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	extension := filepath.Join(home, ".vscode", "extensions", "anthropic.claude-code-2.1.280")
	if err := os.MkdirAll(extension, 0700); err != nil {
		t.Fatal(err)
	}

	detection := DetectClaudeCode()
	if !detection.Found || detection.Source != "VS Code extension" || detection.Path != extension {
		t.Fatalf("unexpected detection: %#v", detection)
	}
}

func TestDetectCodexVSCodeExtension(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	extension := filepath.Join(home, ".vscode-insiders", "extensions", "openai.chatgpt-1.0.0")
	if err := os.MkdirAll(extension, 0700); err != nil {
		t.Fatal(err)
	}

	detection := DetectCodexVSCode()
	if !detection.Found || detection.Source != "VS Code extension" || detection.Path != extension {
		t.Fatalf("unexpected detection: %#v", detection)
	}
}

func TestDetectClaudeCodeSharedSettings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	settings := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}

	detection := DetectClaudeCode()
	if !detection.Found || detection.Source != "shared Claude settings" || detection.Path != settings {
		t.Fatalf("unexpected detection: %#v", detection)
	}
}

func TestInspectCodexVSCodeExtensionWithoutCLI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	extension := filepath.Join(home, ".vscode", "extensions", "openai.chatgpt-1.2.3")
	if err := os.MkdirAll(extension, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extension, "package.json"), []byte(`{"version":"1.2.3"}`), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("[features]\nhooks = true\n"), 0600); err != nil {
		t.Fatal(err)
	}

	status := InspectCodex()
	if status.State != CodexHookEnabled || status.Version != "VS Code extension 1.2.3" {
		t.Fatalf("unexpected Codex status: %#v", status)
	}
}

func TestInspectCodexIndividuallyDisabledHooks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	extension := filepath.Join(home, ".vscode", "extensions", "openai.chatgpt-1.2.3")
	if err := os.MkdirAll(extension, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0700); err != nil {
		t.Fatal(err)
	}
	hooks := `{"hooks":{"SessionStart":[{"hooks":[{"command":"echo unrelated"},{"command":"secuarden hook codex-session-start"}]}]}}`
	if err := os.WriteFile(codexHooksPath(), []byte(hooks), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, suffix string
		disabled     bool
	}{
		{"our current handler", ":session_start:0:1", true},
		{"other handler", ":session_start:0:0", false},
		{"stale handler", ":session_start:0:2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := "[features]\nhooks = true\n[hooks.state.\"" + codexHooksPath() + tc.suffix + "\"]\nenabled = false\n"
			if err := os.WriteFile(codexConfigPath(), []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			status := InspectCodex()
			if (status.State == CodexHookDisabled) != tc.disabled {
				t.Fatalf("status: %+v", status)
			}
		})
	}
}
