package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// secuardenHookEntry is the hook definition we inject into settings.json.
type hookEntry struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Timeout int      `json:"timeout"`
	Async   bool     `json:"async"`
}

type hookMatcher struct {
	Matcher string      `json:"matcher,omitempty"`
	Hooks   []hookEntry `json:"hooks"`
}

// secuardenHooks is the configuration block we merge into settings.json.
var secuardenHooks = map[string][]hookMatcher{
	"PreToolUse": {
		{
			Matcher: "*",
			Hooks: []hookEntry{
				{Type: "command", Command: "secuarden", Args: []string{"hook", "pre-tool-use"}, Timeout: 5, Async: true},
			},
		},
	},
	"PostToolUse": {
		{
			Matcher: "*",
			Hooks: []hookEntry{
				{Type: "command", Command: "secuarden", Args: []string{"hook", "post-tool-use"}, Timeout: 5, Async: true},
			},
		},
	},
	"SessionStart": {
		{
			Hooks: []hookEntry{
				{Type: "command", Command: "secuarden", Args: []string{"hook", "session-start"}, Timeout: 5, Async: true},
			},
		},
	},
	"SessionEnd": {
		{
			Hooks: []hookEntry{
				// Async: false so Claude Code waits for the process and the developer
				// sees SaaS feedback printed to stdout when sync is enabled.
				// The binary exits in <10ms when sync is disabled, so the wait is negligible.
				{Type: "command", Command: "secuarden", Args: []string{"hook", "session-end"}, Timeout: 10, Async: false},
			},
		},
	},
}

// InstallHooks merges Secuarden hooks into ~/.claude/settings.json.
// It backs up the file first and preserves all existing hooks.
func InstallHooks() error {
	settingsPath := claudeSettingsPath()

	// Read existing settings
	settings, err := readSettings(settingsPath)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}

	// Back up before modifying
	if err := backupSettings(settingsPath); err != nil {
		return fmt.Errorf("backup settings: %w", err)
	}

	// Ensure hooks key exists
	hooksRaw, _ := settings["hooks"]
	var hooks map[string]interface{}
	if hooksRaw != nil {
		if h, ok := hooksRaw.(map[string]interface{}); ok {
			hooks = h
		}
	}
	if hooks == nil {
		hooks = make(map[string]interface{})
	}

	// Merge our hooks into each event type
	for event, matchers := range secuardenHooks {
		existing := getMatcherList(hooks[event])
		// Remove any stale secuarden entries first
		existing = removeSecuardenEntries(existing)
		// Add our entries
		for _, m := range matchers {
			mb, _ := json.Marshal(m)
			var mRaw interface{}
			_ = json.Unmarshal(mb, &mRaw)
			existing = append(existing, mRaw)
		}
		hooks[event] = existing
	}

	settings["hooks"] = hooks

	// Write back with 2-space indent
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}

	// Verify the file is still valid JSON
	var verify interface{}
	if err := json.Unmarshal(data, &verify); err != nil {
		return fmt.Errorf("settings file corrupted after write: %w", err)
	}

	return nil
}

// RemoveHooks removes only Secuarden hook entries from ~/.claude/settings.json.
func RemoveHooks() error {
	settingsPath := claudeSettingsPath()

	settings, err := readSettings(settingsPath)
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}

	hooksRaw, ok := settings["hooks"]
	if !ok {
		return nil // nothing to remove
	}
	hooks, ok := hooksRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	for event := range secuardenHooks {
		existing := getMatcherList(hooks[event])
		cleaned := removeSecuardenEntries(existing)
		if len(cleaned) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = cleaned
		}
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"] = hooks
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(settingsPath, data, 0644)
}

// HooksInstalled returns true if Secuarden hooks are present in settings.json.
func HooksInstalled() bool {
	settingsPath := claudeSettingsPath()
	settings, err := readSettings(settingsPath)
	if err != nil {
		return false
	}
	hooksRaw, ok := settings["hooks"]
	if !ok {
		return false
	}
	hooks, ok := hooksRaw.(map[string]interface{})
	if !ok {
		return false
	}
	for event := range secuardenHooks {
		matchers := getMatcherList(hooks[event])
		for _, m := range matchers {
			if isSecuardenEntry(m) {
				return true
			}
		}
	}
	return false
}

func readSettings(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]interface{}), nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return make(map[string]interface{}), nil
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("invalid JSON in settings file: %w", err)
	}
	return settings, nil
}

func backupSettings(settingsPath string) error {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	backupDir := filepath.Join(home, ".secuarden", "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return err
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	backupPath := filepath.Join(backupDir, "settings.json."+ts)
	return os.WriteFile(backupPath, data, 0600)
}

func getMatcherList(v interface{}) []interface{} {
	if v == nil {
		return nil
	}
	if list, ok := v.([]interface{}); ok {
		return list
	}
	return nil
}

// isSecuardenEntry returns true if a matcher entry is one of ours.
func isSecuardenEntry(v interface{}) bool {
	m, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	hooks, _ := m["hooks"].([]interface{})
	for _, h := range hooks {
		hm, ok := h.(map[string]interface{})
		if !ok {
			continue
		}
		if cmd, _ := hm["command"].(string); cmd == "secuarden" {
			if args, _ := hm["args"].([]interface{}); len(args) > 0 {
				if first, _ := args[0].(string); first == "hook" {
					return true
				}
			}
		}
	}
	return false
}

func removeSecuardenEntries(matchers []interface{}) []interface{} {
	var result []interface{}
	for _, m := range matchers {
		if !isSecuardenEntry(m) {
			result = append(result, m)
		}
	}
	return result
}
