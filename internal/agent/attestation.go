package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/secuardenai/secuarden-cli/internal/attestation"
	"github.com/secuardenai/secuarden-cli/internal/capturecontract"
)

// ObserveCaptureConfiguration evaluates binary-defined requirements, never a
// user-accepted snapshot. Scope is shared user-level configuration only: project
// overrides, runtime activation and actual delivery are not certified here.
func ObserveCaptureConfiguration(names []string) attestation.Snapshot {
	s := attestation.Snapshot{}
	add := func(id, status, reason string) {
		s.Results = append(s.Results, attestation.RequirementResult{ID: id, Status: status, Reason: reason})
		if status != "pass" {
			s.Problems = append(s.Problems, id+": "+reason)
		}
		if status == "unknown" {
			s.Unknown = true
		}
	}
	executableCache := map[string]string{}
	approved, approvedErr := installedExecutable()
	var approvedDigest string
	if approvedErr == nil {
		approvedDigest, approvedErr = captureExecutableDigest(approved)
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	for _, name := range sorted {
		contract, err := capturecontract.For(name)
		if err != nil {
			add(name+"/contract", "unknown", "unsupported adapter")
			continue
		}
		s.Contracts = append(s.Contracts, attestation.ContractRef{Adapter: name, Version: contract.Version, Digest: contract.Digest()})
		path := claudeSettingsPath()
		if name == "codex" {
			path = codexHooksPath()
		}
		data, readErr := os.ReadFile(path)
		var settings map[string]any
		parseErr := error(nil)
		if readErr == nil {
			parseErr = json.Unmarshal(data, &settings)
		}
		if readErr != nil || parseErr != nil || settings == nil {
			status := "unknown"
			if os.IsNotExist(readErr) {
				status = "fail"
			}
			add(name+"/configuration", status, "hook configuration unavailable or malformed")
			for _, h := range contract.Hooks {
				add(name+"/"+h.Event, status, "cannot inspect required hook")
			}
			continue
		}
		add(name+"/configuration", "pass", "")
		if disabled, ok := settings["disableAllHooks"]; ok {
			value, valid := disabled.(bool)
			if !valid {
				add(name+"/hooks_enabled", "unknown", "invalid global enablement")
			} else if value {
				add(name+"/hooks_enabled", "fail", "all hooks disabled")
			} else {
				add(name+"/hooks_enabled", "pass", "")
			}
		} else {
			add(name+"/hooks_enabled", "pass", "")
		}
		hooks, valid := settings["hooks"].(map[string]any)
		for _, h := range contract.Hooks {
			id := name + "/" + h.Event
			if !valid {
				add(id, "unknown", "hooks must be an object")
				continue
			}
			candidates := []struct{ group, hook map[string]any }{}
			for _, entry := range getMatcherList(hooks[h.Event]) {
				group, _ := entry.(map[string]any)
				entries, _ := group["hooks"].([]any)
				for _, raw := range entries {
					hook, _ := raw.(map[string]any)
					if isSecuardenEntry(map[string]any{"hooks": []any{hook}}) {
						candidates = append(candidates, struct{ group, hook map[string]any }{group, hook})
					}
				}
			}
			if len(candidates) != 1 {
				add(id, "fail", "exactly one Secuarden capture handler is required")
				continue
			}
			candidate := candidates[0]
			reason := validateCaptureHook(h, candidate.group, candidate.hook)
			if reason != "" {
				add(id, "fail", reason)
				continue
			}
			if approvedErr != nil {
				add(id, "unknown", "cannot identify the running collector build")
				continue
			}
			command, _ := candidate.hook["command"].(string)
			resolved, err := exec.LookPath(configuredExecutable(command))
			if err != nil {
				add(id, "fail", "collector is not executable")
				continue
			}
			value, ok := executableCache[resolved]
			if !ok {
				value, err = captureExecutableDigest(resolved)
				if err != nil {
					add(id, "unknown", "collector cannot be inspected")
					continue
				}
				executableCache[resolved] = value
			}
			if value != approvedDigest {
				add(id, "fail", "collector differs from the running CLI build; refresh hooks after upgrading")
				continue
			}
			add(id, "pass", "")
		}
		if contract.CodexFeatureEnabled {
			cfg, err := readCodexConfig(codexConfigPath())
			if err != nil {
				add(name+"/runtime_enablement", "unknown", "runtime settings cannot be inspected")
			} else if !cfg.Features["hooks"] && !cfg.Features["codex_hooks"] {
				add(name+"/runtime_enablement", "fail", "hooks feature disabled")
			} else {
				add(name+"/runtime_enablement", "pass", "")
			}
			if err != nil {
				add(name+"/individual_hooks_enabled", "unknown", "runtime settings cannot be inspected")
			} else if len(disabledCodexHooks(cfg)) > 0 {
				add(name+"/individual_hooks_enabled", "fail", "required hooks disabled: "+strings.Join(disabledCodexHooks(cfg), ", "))
			} else {
				add(name+"/individual_hooks_enabled", "pass", "")
			}
		}
	}
	sort.Strings(s.Problems)
	sort.Slice(s.Results, func(i, j int) bool { return s.Results[i].ID < s.Results[j].ID })
	return s
}

func validateCaptureHook(required capturecontract.Hook, group, hook map[string]any) string {
	if hook["type"] != "command" {
		return "capture handler must be a command"
	}
	matcher, present := group["matcher"]
	if present && matcher != "" && matcher != "*" {
		return "matcher excludes required events"
	}
	for _, item := range []map[string]any{group, hook} {
		if enabled, ok := item["enabled"]; ok && enabled != true {
			return "required hook is not enabled"
		}
	}
	command, ok := hook["command"].(string)
	if !ok {
		return "handler command is missing"
	}
	args, hasArgs := hook["args"]
	if index := strings.LastIndex(command, " hook "); index >= 0 {
		if command[index:] != " hook "+required.Handler {
			return "incorrect capture handler or extra command arguments"
		}
		if hasArgs && args != nil {
			list, ok := args.([]any)
			if !ok || len(list) != 0 {
				return "unexpected handler arguments"
			}
		}
	} else {
		list, ok := args.([]any)
		if !ok || len(list) != 2 || list[0] != "hook" || list[1] != required.Handler {
			return "incorrect capture handler arguments"
		}
	}
	// Accept only the executable quoting emitted by installers (and plain paths).
	// Never interpret shell expressions, prefixes, wrappers or redirection.
	executable := configuredExecutable(command)
	prefix := command
	if index := strings.LastIndex(command, " hook "); index >= 0 {
		prefix = command[:index]
	}
	if prefix != shellQuote(executable) && prefix != "\""+executable+"\"" && prefix != executable {
		return "unsupported executable command syntax"
	}
	if strings.ContainsAny(executable, "\n\r`$") {
		return "shell expansions are not supported in capture commands"
	}
	if prefix == "\""+executable+"\"" && strings.ContainsAny(executable, "\\\"") {
		return "unsupported quoted executable syntax"
	}
	if prefix == executable && strings.ContainsAny(prefix, " \t;&|<>()*?[]{}!~\\\"'") {
		return "unquoted executable command syntax"
	}
	timeout, ok := hook["timeout"].(float64)
	if !ok || timeout < float64(required.MinTimeout) {
		return fmt.Sprintf("explicit timeout must be at least %d seconds", required.MinTimeout)
	}
	async := false
	if value, present := hook["async"]; present {
		var valid bool
		async, valid = value.(bool)
		if !valid {
			return "invalid async setting"
		}
	}
	if required.Synchronous && async {
		return "capture handler must execute synchronously"
	}
	return ""
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
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
