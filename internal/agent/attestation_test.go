package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
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

func TestEmbeddedContractRejectsBadInitialSettings(t *testing.T) {
	for _, name := range []string{"claude-code", "codex"} {
		for _, test := range []struct {
			name   string
			mutate func(map[string]any, map[string]any)
		}{
			{"wrong handler", func(_, h map[string]any) { h["command"] = h["command"].(string) + "-wrong" }},
			{"extra args", func(_, h map[string]any) { h["command"] = h["command"].(string) + " --ignore" }},
			{"narrow matcher", func(g, h map[string]any) { g["matcher"] = "Read" }},
			{"async pre", func(_, h map[string]any) { h["async"] = true }},
			{"short timeout", func(_, h map[string]any) { h["timeout"] = 1 }},
			{"disabled", func(_, h map[string]any) { h["enabled"] = false }},
			{"wrong type", func(_, h map[string]any) { h["type"] = "prompt" }},
		} {
			t.Run(name+"/"+test.name, func(t *testing.T) {
				attestationTestHome(t)
				path := claudeSettingsPath()
				if name == "codex" {
					path = codexHooksPath()
					if e := InstallCodexHooks(); e != nil {
						t.Fatal(e)
					}
					os.WriteFile(codexConfigPath(), []byte("[features]\nhooks=true\n"), 0600)
				} else if e := InstallHooks(); e != nil {
					t.Fatal(e)
				}
				data, _ := os.ReadFile(path)
				var settings map[string]any
				json.Unmarshal(data, &settings)
				group := settings["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
				hook := group["hooks"].([]any)[0].(map[string]any)
				test.mutate(group, hook)
				data, _ = json.Marshal(settings)
				os.WriteFile(path, data, 0600)
				got := ObserveCaptureConfiguration([]string{name})
				if len(got.Problems) == 0 {
					t.Fatal("accepted invalid first configuration")
				}
			})
		}
	}
}
func TestContractAllowsHarmlessChanges(t *testing.T) {
	attestationTestHome(t)
	InstallHooks()
	baseline := ObserveCaptureConfiguration([]string{"claude-code"})
	data, _ := os.ReadFile(claudeSettingsPath())
	var settings map[string]any
	json.Unmarshal(data, &settings)
	for _, entries := range settings["hooks"].(map[string]any) {
		for _, raw := range entries.([]any) {
			g := raw.(map[string]any)
			g["description"] = "harmless label"
			for _, raw := range g["hooks"].([]any) {
				h := raw.(map[string]any)
				h["timeout"] = 120
				h["description"] = "new label"
			}
		}
	}
	data, _ = json.Marshal(settings)
	os.WriteFile(claudeSettingsPath(), data, 0600)
	if got := ObserveCaptureConfiguration([]string{"claude-code"}); !reflect.DeepEqual(got, baseline) {
		t.Fatalf("harmless settings changed compliance: %+v", got)
	}
}
func TestContractRejectsSubstituteCollector(t *testing.T) {
	attestationTestHome(t)
	InstallHooks()
	binary, _ := installedExecutable()
	// Different executable bytes cannot be legitimized by taking a new snapshot.
	substitute := filepath.Join(t.TempDir(), "secuarden")
	os.WriteFile(substitute, []byte("#!/bin/sh\nexit 1\n"), 0700)
	data, _ := os.ReadFile(claudeSettingsPath())
	data = []byte(strings.ReplaceAll(string(data), binary, substitute))
	os.WriteFile(claudeSettingsPath(), data, 0600)
	if got := ObserveCaptureConfiguration([]string{"claude-code"}); len(got.Problems) == 0 {
		t.Fatal("accepted substitute collector")
	}
}

func TestContractIgnoresUnrelatedCodexTrustAndDetectsHookState(t *testing.T) {
	attestationTestHome(t)
	if e := InstallCodexHooks(); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(codexConfigPath(), []byte("[features]\nhooks=true\n"), 0600)
	baseline := ObserveCaptureConfiguration([]string{"codex"})
	os.WriteFile(codexConfigPath(), []byte("[features]\nhooks=true\n[projects.\"/unrelated\"]\ntrust_level=\"untrusted\"\n"), 0600)
	if got := ObserveCaptureConfiguration([]string{"codex"}); !reflect.DeepEqual(got, baseline) {
		t.Fatal("unrelated project trust changed compliance")
	}
	id := codexHooksPath() + ":pre_tool_use:0:0"
	os.WriteFile(codexConfigPath(), []byte("[features]\nhooks=true\n[hooks.state."+strconv.Quote(id)+"]\nenabled=false\n"), 0600)
	if got := ObserveCaptureConfiguration([]string{"codex"}); len(got.Problems) == 0 {
		t.Fatal("disabled required hook was accepted")
	}
}
func TestContractAllowsRelocatedIdenticalCollectorAndLegacyArgs(t *testing.T) {
	attestationTestHome(t)
	InstallHooks()
	baseline := ObserveCaptureConfiguration([]string{"claude-code"})
	binary, _ := installedExecutable()
	bytes, _ := os.ReadFile(binary)
	copy := filepath.Join(t.TempDir(), "secuarden")
	os.WriteFile(copy, bytes, 0700)
	data, _ := os.ReadFile(claudeSettingsPath())
	var settings map[string]any
	json.Unmarshal(data, &settings)
	for _, raw := range settings["hooks"].(map[string]any) {
		for _, raw := range raw.([]any) {
			group := raw.(map[string]any)
			for _, raw := range group["hooks"].([]any) {
				hook := raw.(map[string]any)
				command := hook["command"].(string)
				index := strings.LastIndex(command, " hook ")
				handler := command[index+6:]
				hook["command"] = shellQuote(copy)
				hook["args"] = []string{"hook", handler}
			}
		}
	}
	data, _ = json.Marshal(settings)
	os.WriteFile(claudeSettingsPath(), data, 0600)
	if got := ObserveCaptureConfiguration([]string{"claude-code"}); !reflect.DeepEqual(got, baseline) {
		t.Fatalf("equivalent collector invocation changed compliance: %+v", got)
	}
}
