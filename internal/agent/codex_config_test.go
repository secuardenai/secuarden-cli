package agent

import (
	"strings"
	"testing"
)

func TestParseCodexConfig(t *testing.T) {
	config, err := parseCodexConfig(strings.NewReader(`
personality = "pragmatic"

[features]
codex_hooks = true # explicitly enabled

[projects."/work/repo"]
trust_level = "trusted"
`), codexConfig{Features: map[string]bool{}, Present: map[string]bool{}, Trust: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if enabled, ok := config.feature("codex_hooks"); !ok || !enabled {
		t.Fatalf("codex_hooks = (%v, %v), want (true, true)", enabled, ok)
	}
	if got := config.projectTrust("/work/repo"); got != "trusted" {
		t.Fatalf("trust level = %q, want trusted", got)
	}
}

func TestParseCodexConfigRejectsMalformedFeature(t *testing.T) {
	_, err := parseCodexConfig(strings.NewReader("[features]\ncodex_hooks = maybe\n"), codexConfig{Features: map[string]bool{}, Present: map[string]bool{}, Trust: map[string]string{}})
	if err == nil {
		t.Fatal("expected malformed feature error")
	}
}

func TestSetCodexFeaturePreservesConfiguration(t *testing.T) {
	input := "model = \"gpt\"\n\n[features]\n# keep this comment\ncodex_hooks = false # user setting\n\n[projects.\"/work/repo\"]\ntrust_level = \"trusted\"\n"
	got, changed := setCodexFeature(input, "codex_hooks", true)
	if !changed {
		t.Fatal("expected configuration to change")
	}
	if !strings.Contains(got, "# keep this comment") || !strings.Contains(got, "codex_hooks = true # user setting") || !strings.Contains(got, "trust_level = \"trusted\"") {
		t.Fatalf("configuration was not preserved:\n%s", got)
	}
}

func TestSetCodexFeatureAddsExistingFeaturesTable(t *testing.T) {
	input := "model = \"gpt\"\n\n[features]\njs_repl = false\n\n[projects.\"/work/repo\"]\ntrust_level = \"trusted\"\n"
	got, changed := setCodexFeature(input, "hooks", true)
	if !changed || !strings.Contains(got, "[features]\njs_repl = false") || !strings.Contains(got, "hooks = true") {
		t.Fatalf("feature was not added to existing table:\n%s", got)
	}
}

func TestParseCodexHookDisabledState(t *testing.T) {
	config, err := parseCodexConfig(strings.NewReader(`[features]
hooks = true
[hooks.state."/home/test/.codex/hooks.json:session_start:0:0"]
trusted_hash = "sha256:keep"
enabled = false
`), codexConfig{Features: map[string]bool{}, Present: map[string]bool{}, Trust: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if enabled, present := config.HookEnabled["/home/test/.codex/hooks.json:session_start:0:0"]; !present || enabled {
		t.Fatal("individual disable lost")
	}
}
