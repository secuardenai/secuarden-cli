package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMixedHookGroupsSurviveRefreshAndRemoval(t *testing.T) {
	for _, agent := range []struct {
		name, path      string
		install, remove func() error
	}{
		{"claude", ".claude/settings.json", InstallHooks, RemoveHooks},
		{"codex", ".codex/hooks.json", InstallCodexHooks, RemoveCodexHooks},
	} {
		t.Run(agent.name, func(t *testing.T) {
			home := t.TempDir()
			patchHome(t, home)
			path := filepath.Join(home, agent.path)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			original := `{"extra":"keep","hooks":{"PreToolUse":[{"matcher":"Read|Write","extra":{"preserve":true},"hooks":[{"type":"command","command":"other-before","async":true},{"type":"command","command":"/old/secuarden hook pre-tool-use"},{"type":"command","command":"/old/secuarden","args":["hook","pre-tool-use"]},{"type":"command","command":"/old/secuarden observe-codex"},{"type":"command","command":"secuarden-wrapper hook pre-tool-use"},{"type":"command","command":"other-after","timeout":9}]}]}}`
			var want map[string]interface{}
			if err := json.Unmarshal([]byte(original), &want); err != nil {
				t.Fatal(err)
			}
			group := want["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})[0].(map[string]interface{})
			hooks := group["hooks"].([]interface{})
			group["hooks"] = append(hooks[:1:1], hooks[3:]...)
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if err := agent.install(); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var got map[string]interface{}
				if err := json.Unmarshal(data, &got); err != nil {
					t.Fatal(err)
				}
				groups := got["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
				if len(groups) != 2 || !reflect.DeepEqual(groups[0], group) {
					t.Fatalf("refresh lost mixed group: %s", data)
				}
			}
			if err := agent.remove(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]interface{}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("uninstall changed unrelated settings: %s", data)
			}
		})
	}
}
