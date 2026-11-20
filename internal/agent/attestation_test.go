package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAttestationSemanticChangesAndRestoration(t *testing.T) {
	attestationTestHome(t)
	if err := InstallHooks(); err != nil {
		t.Fatal(err)
	}
	original := ObserveCaptureConfiguration([]string{"claude-code"})
	if len(original.Problems) > 0 {
		t.Fatal(original.Problems)
	}
	path := claudeSettingsPath()
	data, _ := os.ReadFile(path)
	var settings map[string]any
	json.Unmarshal(data, &settings)
	settings["unrelatedCredential"] = "DO-NOT-RETAIN"
	hooks := settings["hooks"].(map[string]any)
	hooks["PreToolUse"] = append(hooks["PreToolUse"].([]any), map[string]any{"hooks": []any{map[string]any{"type": "command", "command": "unrelated"}}})
	write := func() {
		b, _ := json.MarshalIndent(settings, "", "    ")
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write()
	if got := ObserveCaptureConfiguration([]string{"claude-code"}); !reflect.DeepEqual(original, got) {
		t.Fatalf("unrelated settings changed snapshot: %+v", got)
	}
	saved := hooks["PostToolUse"]
	delete(hooks, "PostToolUse")
	write()
	if got := ObserveCaptureConfiguration([]string{"claude-code"}); len(got.Problems) == 0 || reflect.DeepEqual(original, got) {
		t.Fatal("missing hook undetected")
	}
	hooks["PostToolUse"] = saved
	write()
	if got := ObserveCaptureConfiguration([]string{"claude-code"}); !reflect.DeepEqual(original, got) {
		t.Fatal("restoration not matched")
	}
	os.WriteFile(path, []byte("{"), 0600)
	if got := ObserveCaptureConfiguration([]string{"claude-code"}); !got.Unknown {
		t.Fatal("invalid JSON not unknown")
	}
	os.Remove(path)
	if got := ObserveCaptureConfiguration([]string{"claude-code"}); len(got.Problems) == 0 {
		t.Fatal("missing settings ignored")
	}
}
func TestAttestationCodexDisabling(t *testing.T) {
	attestationTestHome(t)
	if err := InstallCodexHooks(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(os.Getenv("HOME"), ".codex", "config.toml")
	os.WriteFile(path, []byte("[features]\ncodex_hooks = true\n"), 0600)
	baseline := ObserveCaptureConfiguration([]string{"codex"})
	if len(baseline.Problems) > 0 {
		t.Fatal(baseline.Problems)
	}
	os.WriteFile(path, []byte("[features]\ncodex_hooks = false\n"), 0600)
	got := ObserveCaptureConfiguration([]string{"codex"})
	if len(got.Problems) == 0 || reflect.DeepEqual(baseline, got) {
		t.Fatal("disabled feature not detected")
	}
}

func attestationTestHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if e := os.MkdirAll(filepath.Dir(claudeSettingsPath()), 0700); e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(t.TempDir(), "secuarden")
	if e := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0700); e != nil {
		t.Fatal(e)
	}
	old := installedExecutable
	installedExecutable = func() (string, error) { return binary, nil }
	t.Cleanup(func() { installedExecutable = old })
}
