package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func tempSettings(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	if content != "" {
		if err := os.WriteFile(settingsPath, []byte(content), 0644); err != nil {
			t.Fatalf("write temp settings: %v", err)
		}
	}
	return settingsPath
}

// patchSettingsPath overrides the settings path used by agent functions for testing.
// It restores the real HOME after the test.
func patchHome(t *testing.T, home string) {
	t.Helper()
	orig := os.Getenv("HOME")
	os.Setenv("HOME", home)
	t.Cleanup(func() { os.Setenv("HOME", orig) })
}

func TestInstallHooks_EmptySettings(t *testing.T) {
	dir := t.TempDir()
	claudeDir := filepath.Join(dir, ".claude")
	_ = os.MkdirAll(claudeDir, 0700)
	_ = os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte("{}"), 0644)

	patchHome(t, dir)

	if err := InstallHooks(); err != nil {
		t.Fatalf("InstallHooks: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("invalid JSON after install: %v", err)
	}

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		t.Fatal("expected hooks key in settings")
	}
	for _, event := range []string{"PreToolUse", "PostToolUse", "SessionStart", "SessionEnd"} {
		if _, ok := hooks[event]; !ok {
			t.Errorf("expected hook for %s", event)
		}
	}
}

func TestInstallHooks_PreservesExistingHooks(t *testing.T) {
	existing := `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {"type": "command", "command": "other-tool", "args": ["--check"]}
        ]
      }
    ]
  }
}`
	dir := t.TempDir()
	claudeDir := filepath.Join(dir, ".claude")
	_ = os.MkdirAll(claudeDir, 0700)
	_ = os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(existing), 0644)
	patchHome(t, dir)

	if err := InstallHooks(); err != nil {
		t.Fatalf("InstallHooks: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	var settings map[string]interface{}
	_ = json.Unmarshal(data, &settings)

	hooks := settings["hooks"].(map[string]interface{})
	preList := hooks["PreToolUse"].([]interface{})

	// Should have both: the existing other-tool entry and our secuarden entry
	if len(preList) < 2 {
		t.Errorf("expected at least 2 PreToolUse matchers, got %d", len(preList))
	}

	// Verify the other-tool hook is preserved
	foundOther := false
	for _, entry := range preList {
		m, _ := entry.(map[string]interface{})
		hooksArr, _ := m["hooks"].([]interface{})
		for _, h := range hooksArr {
			hm, _ := h.(map[string]interface{})
			if hm["command"] == "other-tool" {
				foundOther = true
			}
		}
	}
	if !foundOther {
		t.Error("existing other-tool hook was removed")
	}
}

func TestRemoveHooks(t *testing.T) {
	dir := t.TempDir()
	claudeDir := filepath.Join(dir, ".claude")
	_ = os.MkdirAll(claudeDir, 0700)
	_ = os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte("{}"), 0644)
	patchHome(t, dir)

	_ = InstallHooks()

	if !HooksInstalled() {
		t.Fatal("hooks should be installed after InstallHooks")
	}

	if err := RemoveHooks(); err != nil {
		t.Fatalf("RemoveHooks: %v", err)
	}

	if HooksInstalled() {
		t.Error("hooks should not be installed after RemoveHooks")
	}
}

func TestInstallHooks_Idempotent(t *testing.T) {
	dir := t.TempDir()
	claudeDir := filepath.Join(dir, ".claude")
	_ = os.MkdirAll(claudeDir, 0700)
	_ = os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte("{}"), 0644)
	patchHome(t, dir)

	_ = InstallHooks()
	_ = InstallHooks() // second call

	data, _ := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	var settings map[string]interface{}
	_ = json.Unmarshal(data, &settings)

	hooks := settings["hooks"].(map[string]interface{})
	preList := hooks["PreToolUse"].([]interface{})

	// Should have exactly one secuarden entry
	count := 0
	for _, entry := range preList {
		if isSecuardenEntry(entry) {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 secuarden entry after 2 installs, got %d", count)
	}
}

func TestInstallHooks_MissingFile(t *testing.T) {
	dir := t.TempDir()
	claudeDir := filepath.Join(dir, ".claude")
	_ = os.MkdirAll(claudeDir, 0700)
	// No settings.json — it's missing (first run of Claude Code)
	patchHome(t, dir)

	if err := InstallHooks(); err != nil {
		t.Fatalf("InstallHooks with missing file: %v", err)
	}
	// File should have been created
	if _, err := os.Stat(filepath.Join(claudeDir, "settings.json")); err != nil {
		t.Error("settings.json should have been created")
	}
}
