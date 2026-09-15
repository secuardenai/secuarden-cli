package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	codexadapter "github.com/secuardenai/secuarden-cli/internal/adapters/codex"
)

var codexHooks = map[string]map[string]interface{}{
	"UserPromptSubmit":  {"hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-user-prompt-submit", "timeout": 5, "async": true}}},
	"PreToolUse":        {"matcher": "*", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-pre-tool-use", "timeout": 5}}},
	"PermissionRequest": {"matcher": "*", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-permission-request", "timeout": 5}}},
	"PostToolUse":       {"matcher": "*", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-post-tool-use", "timeout": 5, "async": true}}},
	"SessionStart":      {"hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-session-start", "timeout": 5, "async": true}}},
	"SessionEnd":        {"hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-session-end", "timeout": 10}}},
}

func IsCodexInstalled() bool {
	return CodexHooksSupported()
}

// CodexHooksSupported gates installation on the actual installed CLI exposing
// its hook-trust surface. A config directory alone is not proof of support.
func CodexHooksSupported() bool {
	if _, err := exec.LookPath("codex"); err != nil {
		return false
	}
	output, err := exec.Command("codex", "--help").CombinedOutput()
	if err != nil {
		return false
	}
	return len(output) > 0 && (contains(string(output), "hook-trust") || contains(string(output), "hooks"))
}

func contains(value, needle string) bool {
	return len(value) >= len(needle) && strings.Contains(value, needle)
}

func codexHooksPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".codex", "hooks.json")
}

func InstallCodexHooks() error {
	implementation := codexadapter.Adapter{}
	if err := implementation.Descriptor().Validate(); err != nil {
		return fmt.Errorf("Codex adapter descriptor: %w", err)
	}
	if err := implementation.Capabilities().Validate(); err != nil {
		return fmt.Errorf("Codex adapter capabilities: %w", err)
	}
	path := codexHooksPath()
	if path == "" {
		return fmt.Errorf("resolve Codex hooks path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	settings, err := readSettings(path)
	if err != nil {
		return fmt.Errorf("read Codex hooks: %w", err)
	}
	if err := backupCodexHooks(path); err != nil {
		return fmt.Errorf("backup Codex hooks: %w", err)
	}
	hooks, _ := settings["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = make(map[string]interface{})
	}
	for event, ours := range codexHooks {
		list := getMatcherList(hooks[event])
		list = removeSecuardenEntries(list)
		list = append(list, ours)
		hooks[event] = list
	}
	settings["hooks"] = hooks
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0644)
}

func RemoveCodexHooks() error {
	path := codexHooksPath()
	settings, err := readSettings(path)
	if err != nil {
		return fmt.Errorf("read Codex hooks: %w", err)
	}
	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		return nil
	}
	for event := range codexHooks {
		list := removeSecuardenEntries(getMatcherList(hooks[event]))
		if len(list) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = list
		}
	}
	if len(hooks) == 0 {
		delete(settings, "hooks")
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0644)
}

func CodexHooksInstalled() bool {
	settings, err := readSettings(codexHooksPath())
	if err != nil {
		return false
	}
	hooks, _ := settings["hooks"].(map[string]interface{})
	for event := range codexHooks {
		for _, entry := range getMatcherList(hooks[event]) {
			if isSecuardenEntry(entry) {
				return true
			}
		}
	}
	return false
}

func backupCodexHooks(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".secuarden", "backups")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	name := "codex-hooks.json." + time.Now().UTC().Format("20060102T150405Z")
	return os.WriteFile(filepath.Join(dir, name), data, 0600)
}
