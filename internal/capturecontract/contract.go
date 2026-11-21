// Package capturecontract defines the minimum capture configuration shipped in
// the CLI. It is independent of machine settings, observation and storage.
package capturecontract

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

type Hook struct {
	Event       string `json:"event"`
	Handler     string `json:"handler"`
	Matcher     string `json:"matcher,omitempty"`
	MinTimeout  int    `json:"min_timeout_seconds"`
	Synchronous bool   `json:"synchronous"`
}
type Contract struct {
	Adapter             string `json:"adapter"`
	Version             string `json:"version"`
	Collector           string `json:"collector"`
	GlobalHooksEnabled  bool   `json:"global_hooks_enabled"`
	CodexFeatureEnabled bool   `json:"codex_feature_enabled"`
	Hooks               []Hook `json:"hooks"`
}

// For returns a fresh definition; callers cannot mutate the embedded contract.
func For(adapter string) (Contract, error) {
	c := Contract{Adapter: adapter, Version: "1", Collector: "same-build-as-observer", GlobalHooksEnabled: true}
	prefix := ""
	switch adapter {
	case "claude-code":
	case "codex":
		prefix = "codex-"
		c.CodexFeatureEnabled = true
	default:
		return Contract{}, fmt.Errorf("unsupported capture adapter %q", adapter)
	}
	c.Hooks = []Hook{
		{"SessionStart", prefix + "session-start", "", 5, false},
		{"UserPromptSubmit", prefix + "user-prompt-submit", "", 5, false},
		{"PreToolUse", prefix + "pre-tool-use", "*", 5, true},
		{"PostToolUse", prefix + "post-tool-use", "*", 5, false},
		{"SessionEnd", prefix + "session-end", "", 10, true},
	}
	if adapter == "codex" {
		c.Hooks = append(c.Hooks, Hook{"PermissionRequest", "codex-permission-request", "*", 5, true}, Hook{"Stop", "codex-stop", "", 10, false})
	}
	return c, nil
}
func (c Contract) Digest() string {
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h)
}
