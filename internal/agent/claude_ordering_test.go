package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Refresh must replace old asynchronous pre-hooks: a fast tool can otherwise
// finish before its before-state checkpoint has been persisted.
func TestRefreshClaudePreHookWaitsForCheckpoint(t *testing.T) {
	home := t.TempDir()
	patchHome(t, home)
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	old := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"/old/secuarden hook pre-tool-use","async":true}]},{"matcher":"*","hooks":[{"type":"command","command":"other-tool","async":true}]}]}}`
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := InstallHooks(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Hooks map[string][]struct {
				Hooks []struct {
					Command string `json:"command"`
					Async   bool   `json:"async"`
					Timeout int    `json:"timeout"`
				} `json:"hooks"`
			} `json:"hooks"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		owned, other := 0, 0
		for _, group := range doc.Hooks["PreToolUse"] {
			for _, hook := range group.Hooks {
				if strings.Contains(hook.Command, "hook pre-tool-use") {
					owned++
					if hook.Async {
						t.Fatal("pre-tool checkpoint must finish before the agent runs the tool")
					}
					if hook.Timeout != 5 {
						t.Fatalf("timeout changed: %d", hook.Timeout)
					}
					if strings.Contains(hook.Command, "/old/") {
						t.Fatal("stale executable retained")
					}
				}
				if hook.Command == "other-tool" {
					other++
					if !hook.Async {
						t.Fatal("unrelated hook modified")
					}
				}
			}
		}
		if owned != 1 || other != 1 {
			t.Fatalf("owned=%d other=%d", owned, other)
		}
	}
}
