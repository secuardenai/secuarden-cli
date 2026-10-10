package observationcapture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HookDefinitions returns a separate registration fragment. Explicit merging
// is left to the operator so neither collector rewrites the other's hooks.
// Commands invoke this exact executable and require a separately enabled inbox.
func HookDefinitions(executable, dir string) (map[string]interface{}, error) {
	executable, err := filepath.Abs(executable)
	if err != nil {
		return nil, err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	hooks := map[string]interface{}{}
	for _, event := range HookEvents {
		entry := map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": shellQuote(executable) + " observe-codex --capture-dir " + shellQuote(dir) + " --event " + shellQuote(event), "timeout": 2}}}
		if event == "PreToolUse" || event == "PostToolUse" || event == "PermissionRequest" {
			entry["matcher"] = "*"
		}
		hooks[event] = []interface{}{entry}
	}
	return map[string]interface{}{"hooks": hooks}, nil
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

// MergeHooks preserves unknown fields and legacy entries. Only exact observer
// commands in the generated fragment are deduplicated. It never grants trust.
func MergeHooks(path string, fragment map[string]interface{}) error {
	document := map[string]interface{}{}
	b, err := ReadBounded(path, 4*1024*1024)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil {
		if err = json.Unmarshal(b, &document); err != nil {
			return err
		}
		if document == nil {
			return fmt.Errorf("hooks configuration must be an object")
		}
	}
	hooks, ok := document["hooks"].(map[string]interface{})
	if !ok {
		if document["hooks"] != nil {
			return fmt.Errorf("invalid hooks map")
		}
		hooks = map[string]interface{}{}
	}
	for event, newEntries := range fragment["hooks"].(map[string]interface{}) {
		existing, ok := hooks[event].([]interface{})
		if !ok && hooks[event] != nil {
			return fmt.Errorf("invalid entries for %s", event)
		}
		for _, entry := range newEntries.([]interface{}) {
			encoded, _ := json.Marshal(entry)
			found := false
			for _, old := range existing {
				data, _ := json.Marshal(old)
				if string(data) == string(encoded) {
					found = true
				}
			}
			if !found {
				existing = append(existing, entry)
			}
		}
		hooks[event] = existing
	}
	document["hooks"] = hooks
	b, err = json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return WriteDurable(path, append(b, '\n'))
}
