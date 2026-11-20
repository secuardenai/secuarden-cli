package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"

	"github.com/secuardenai/secuarden-cli/internal/attestation"
	"github.com/secuardenai/secuarden-cli/internal/config"
)

// ObserveCaptureConfiguration reads only user-level capture settings. It never
// executes an agent or hook. Digests avoid retaining commands, trust paths, or secrets.
// Project/managed overrides and actual runtime activation are outside this snapshot.
func ObserveCaptureConfiguration(names []string) attestation.Snapshot {
	s := attestation.Snapshot{Components: map[string]string{}}
	put := func(key string, value any) {
		data, _ := json.Marshal(value)
		h := sha256.Sum256(data)
		s.Components[key] = fmt.Sprintf("%x", h)
	}
	executables := map[string]string{}
	problem := func(label string) { s.Problems = append(s.Problems, label) }
	for _, name := range names {
		path := claudeSettingsPath()
		expected := []string{"SessionStart", "SessionEnd", "UserPromptSubmit", "PreToolUse", "PostToolUse"}
		if name == "codex" {
			path = codexHooksPath()
			expected = append(expected, "PermissionRequest", "Stop")
		} else if name != "claude-code" {
			problem("unsupported agent: " + name)
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			problem(name + ": hook configuration unavailable")
			s.Unknown = s.Unknown || !os.IsNotExist(err)
			continue
		}
		var settings map[string]any
		if json.Unmarshal(data, &settings) != nil || settings == nil {
			problem(name + ": hook configuration unreadable")
			s.Unknown = true
			continue
		}
		disabled, validDisabled := settings["disableAllHooks"].(bool)
		if _, present := settings["disableAllHooks"]; present && !validDisabled {
			problem(name + ": invalid disableAllHooks setting")
			s.Unknown = true
		}
		put(name+"/disableAllHooks", disabled)
		if disabled {
			problem(name + ": all hooks disabled")
		}
		hooks, _ := settings["hooks"].(map[string]any)
		for _, event := range expected {
			entries := []any{}
			for _, entry := range getMatcherList(hooks[event]) {
				matcher, _ := entry.(map[string]any)
				raw, _ := matcher["hooks"].([]any)
				for _, value := range raw {
					hook, _ := value.(map[string]any)
					if !isSecuardenEntry(map[string]any{"hooks": []any{hook}}) {
						continue
					}
					// Preserve behavior-affecting matcher/hook fields; omit unrelated hooks.
					filtered := map[string]any{}
					for k, v := range matcher {
						if k != "hooks" {
							filtered[k] = v
						}
					}
					filtered["hooks"] = []any{hook}
					entries = append(entries, filtered)
					command, _ := hook["command"].(string)
					exe := configuredExecutable(command)
					resolved, err := exec.LookPath(exe)
					if err != nil {
						problem(name + "/" + event + ": executable unavailable")
						continue
					}
					executableDigest, cached := executables[resolved]
					if !cached {
						executableDigest, err = captureExecutableDigest(resolved)
						if err != nil {
							problem(name + "/" + event + ": executable unreadable")
							s.Unknown = true
							continue
						}
						executables[resolved] = executableDigest
					}
					put(name+"/"+event+"/executable", executableDigest)
				}
			}
			if len(entries) == 0 {
				problem(name + "/" + event + ": required hook missing")
			}
			put(name+"/"+event, entries)
		}
		if name == "codex" {
			cfg, err := readCodexConfig(codexConfigPath())
			if err != nil {
				problem("codex: runtime configuration unreadable")
				s.Unknown = true
			} else {
				put("codex/features", cfg.Features)
				put("codex/disabled_hooks", disabledCodexHooks(cfg))
				put("codex/project_trust", cfg.Trust)
				if !cfg.Features["hooks"] && !cfg.Features["codex_hooks"] {
					problem("codex: hooks feature disabled")
				}
				if len(disabledCodexHooks(cfg)) > 0 {
					problem("codex: hook state disabled")
				}
			}
		}
	}
	cfg, err := config.Load()
	if err != nil {
		problem("capture scope unreadable")
		s.Unknown = true
	} else {
		put("capture/scope", struct {
			Scope, Root, Privacy string
			Approved             []string
		}{cfg.CaptureScope, cfg.RepositoryRoot, cfg.PrivacyMode, cfg.ApprovedRepositories})
	}
	sort.Strings(s.Problems)
	return s
}

func captureExecutableDigest(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular executable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular executable")
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%x", path, hash.Sum(nil)), nil
}
