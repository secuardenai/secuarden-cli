package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	codexadapter "github.com/secuardenai/secuarden-cli/internal/adapters/codex"
)

var codexHooks = map[string]map[string]interface{}{
	"UserPromptSubmit":  {"hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-user-prompt-submit", "timeout": 5, "async": true}}},
	"PreToolUse":        {"matcher": "*", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-pre-tool-use", "timeout": 5}}},
	"PermissionRequest": {"matcher": "*", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-permission-request", "timeout": 5}}},
	"PostToolUse":       {"matcher": "*", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-post-tool-use", "timeout": 5, "async": true}}},
	"SessionStart":      {"hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-session-start", "timeout": 5, "async": true}}},
	"SessionEnd":        {"hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-session-end", "timeout": 10}}},
	"Stop":              {"hooks": []interface{}{map[string]interface{}{"type": "command", "command": "secuarden hook codex-stop", "timeout": 10, "async": true}}},
}

type CodexHookState string

const (
	CodexHookUnavailable CodexHookState = "unavailable"
	CodexHookDisabled    CodexHookState = "disabled"
	CodexHookUnsupported CodexHookState = "unsupported"
	CodexHookUntrusted   CodexHookState = "untrusted"
	CodexHookEnabled     CodexHookState = "enabled"
)

// CodexStatus describes the locally installed Codex hook capability without
// modifying the user's Codex configuration.
type CodexStatus struct {
	State      CodexHookState
	Binary     string
	Version    string
	ConfigPath string
	Feature    string
	Reason     string
	Supported  []string
	TrustLevel string
}

var codexRequiredEvents = []string{
	"SessionStart",
	"UserPromptSubmit",
	"PreToolUse",
	"PostToolUse",
	"Stop",
}

func IsCodexInstalled() bool {
	return InspectCodex().State == CodexHookEnabled
}

// CodexHooksSupported gates installation on an explicitly enabled, supported
// Codex hook feature. A binary or config directory alone is not proof of support.
func CodexHooksSupported() bool {
	return InspectCodex().State == CodexHookEnabled
}

// InspectCodex detects the installed CLI, its version, effective hook feature,
// and current project trust without changing any files.
func InspectCodex() CodexStatus {
	status := CodexStatus{State: CodexHookUnavailable, ConfigPath: codexConfigPath()}
	extension := DetectCodexVSCode()
	binary, err := exec.LookPath("codex")
	if err != nil {
		if extension.Found {
			return inspectCodexExtension(status, extension)
		}
		status.Reason = "codex is not on PATH"
		return status
	}
	status.Binary = binary
	versionOutput, err := exec.Command(binary, "--version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(versionOutput)) == "" {
		status.State = CodexHookUnsupported
		status.Reason = "codex --version failed"
		return status
	}
	status.Version = strings.TrimSpace(string(versionOutput))
	helpOutput, err := exec.Command(binary, "--help").CombinedOutput()
	if err != nil || !supportsHookSurface(string(helpOutput)) {
		status.State = CodexHookUnsupported
		status.Reason = "the installed Codex CLI does not advertise hook feature management or hook trust"
		return status
	}
	feature, featureSupported := codexFeatureName(exec.Command(binary, "features", "list"))
	if !featureSupported {
		status.State = CodexHookUnsupported
		status.Reason = "the installed Codex CLI does not advertise a supported hooks feature"
		return status
	}
	status.Feature = feature
	if missing := missingCodexEvents(); len(missing) > 0 {
		status.State = CodexHookUnsupported
		status.Reason = "the Secuarden Codex adapter does not declare required events: " + strings.Join(missing, ", ")
		return status
	}
	config, err := readCodexConfig(status.ConfigPath)
	if err != nil {
		status.State = CodexHookUnsupported
		status.Reason = fmt.Sprintf("cannot parse Codex config: %v", err)
		return status
	}
	status.TrustLevel = config.projectTrust(currentWorkingDirectory())
	if status.TrustLevel != "" && status.TrustLevel != "trusted" {
		status.State = CodexHookUntrusted
		status.Reason = fmt.Sprintf("current project trust level is %q", status.TrustLevel)
		return status
	}
	if enabled, present := config.feature(feature); !present || !enabled {
		status.State = CodexHookDisabled
		status.Reason = fmt.Sprintf("Codex feature %q is not explicitly enabled", feature)
		return status
	}
	if disabled := disabledCodexHooks(config); len(disabled) > 0 {
		status.State = CodexHookDisabled
		status.Reason = "Secuarden hooks individually disabled in Codex: " + strings.Join(disabled, ", ")
		return status
	}
	status.Supported = append([]string(nil), codexRequiredEvents...)
	status.State = CodexHookEnabled
	status.Reason = "Codex hook feature enabled; runtime delivery and current hook trust not verified"
	return status
}

func inspectCodexExtension(status CodexStatus, extension Detection) CodexStatus {
	status.Binary = extension.Path
	status.Feature = "hooks"
	if config, err := readCodexConfig(status.ConfigPath); err != nil {
		status.State = CodexHookUnsupported
		status.Reason = fmt.Sprintf("cannot parse Codex config: %v", err)
		return status
	} else {
		if config.Present["codex_hooks"] {
			status.Feature = "codex_hooks"
		} else if config.Present["hooks"] {
			status.Feature = "hooks"
		}
		status.TrustLevel = config.projectTrust(currentWorkingDirectory())
		if status.TrustLevel != "" && status.TrustLevel != "trusted" {
			status.State = CodexHookUntrusted
			status.Reason = fmt.Sprintf("current project trust level is %q", status.TrustLevel)
			return status
		}
		if disabled := disabledCodexHooks(config); len(disabled) > 0 {
			status.State = CodexHookDisabled
			status.Reason = "Secuarden hooks individually disabled in Codex: " + strings.Join(disabled, ", ")
			return status
		}
		if enabled, present := config.feature(status.Feature); !present || !enabled {
			status.State = CodexHookDisabled
			status.Reason = "Codex hooks are available through the VS Code extension but are not enabled in the Codex configuration"
			return status
		}
	}
	if missing := missingCodexEvents(); len(missing) > 0 {
		status.State = CodexHookUnsupported
		status.Reason = "the Secuarden Codex adapter does not declare required events: " + strings.Join(missing, ", ")
		return status
	}
	status.State = CodexHookEnabled
	status.Version = extensionVersion(extension.Path)
	status.Supported = append([]string(nil), codexRequiredEvents...)
	status.Reason = "Codex VS Code extension and hooks feature configured; runtime delivery and current hook trust not verified"
	return status
}

func extensionVersion(path string) string {
	data, err := os.ReadFile(filepath.Join(path, "package.json"))
	if err != nil {
		return "VS Code extension"
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil || manifest.Version == "" {
		return "VS Code extension"
	}
	return "VS Code extension " + manifest.Version
}

func missingCodexEvents() []string {
	capabilities := codexadapter.Adapter{}.Capabilities()
	missing := make([]string, 0)
	for _, event := range codexRequiredEvents {
		if _, ok := capabilities.ForHook(event); !ok {
			missing = append(missing, event)
		}
	}
	return missing
}

func supportsHookSurface(help string) bool {
	lower := strings.ToLower(help)
	return strings.Contains(lower, "features") &&
		(strings.Contains(lower, "hook-trust") || strings.Contains(lower, "hooks"))
}

func codexFeatureName(command *exec.Cmd) (string, bool) {
	output, err := command.CombinedOutput()
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && (fields[0] == "codex_hooks" || fields[0] == "hooks") {
			return fields[0], true
		}
	}
	return "", false
}

func currentWorkingDirectory() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return filepath.Clean(dir)
}

func codexConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".codex", "config.toml")
}

type codexConfig struct {
	Features    map[string]bool
	Present     map[string]bool
	Trust       map[string]string
	HookEnabled map[string]bool
}

func readCodexConfig(path string) (codexConfig, error) {
	config := codexConfig{Features: map[string]bool{}, Present: map[string]bool{}, Trust: map[string]string{}}
	if path == "" {
		return config, fmt.Errorf("resolve ~/.codex/config.toml")
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return config, nil
	}
	if err != nil {
		return config, err
	}
	defer file.Close()
	return parseCodexConfig(file, config)
}

func parseCodexConfig(input io.Reader, config codexConfig) (codexConfig, error) {
	if config.HookEnabled == nil {
		config.HookEnabled = map[string]bool{}
	}
	scanner := bufio.NewScanner(io.LimitReader(input, 1<<20))
	table := ""
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(stripTOMLComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			table = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if table == "features" && (key == "codex_hooks" || key == "hooks") {
			parsed, err := parseTOMLBool(value)
			if err != nil {
				return config, fmt.Errorf("line %d: %s: %w", lineNumber, key, err)
			}
			if config.Present[key] {
				return config, fmt.Errorf("line %d: duplicate features.%s", lineNumber, key)
			}
			config.Features[key] = parsed
			config.Present[key] = true
			continue
		}
		if strings.HasPrefix(table, "hooks.state.") && key == "enabled" {
			id, err := strconv.Unquote(strings.TrimPrefix(table, "hooks.state."))
			if err != nil {
				return config, fmt.Errorf("line %d: invalid hook state key", lineNumber)
			}
			enabled, err := parseTOMLBool(value)
			if err != nil {
				return config, fmt.Errorf("line %d: invalid hook enabled value", lineNumber)
			}
			if _, exists := config.HookEnabled[id]; exists {
				return config, fmt.Errorf("line %d: duplicate hook enabled value", lineNumber)
			}
			config.HookEnabled[id] = enabled
		}
		if strings.HasPrefix(table, "projects.") && key == "trust_level" {
			project, ok := quotedProjectPath(strings.TrimPrefix(table, "projects."))
			if ok {
				config.Trust[project] = strings.Trim(strings.TrimSpace(value), "\"")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return config, err
	}
	return config, nil
}

func stripTOMLComment(line string) string {
	inString := false
	escaped := false
	for i, r := range line {
		if r == '"' && !escaped {
			inString = !inString
		}
		if r == '#' && !inString {
			return line[:i]
		}
		escaped = r == '\\' && !escaped
		if r != '\\' {
			escaped = false
		}
	}
	return line
}

func parseTOMLBool(value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("expected TOML boolean, got %q", value)
	}
}

func quotedProjectPath(value string) (string, bool) {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", false
	}
	return strings.Trim(value, "\""), true
}

func (c codexConfig) feature(name string) (bool, bool) {
	value, ok := c.Features[name]
	return value, ok
}

func (c codexConfig) projectTrust(path string) string {
	return c.Trust[path]
}

// EnableCodexHooks explicitly enables the discovered Codex hook feature while
// preserving all other bytes, comments, and user configuration.
func EnableCodexHooks() error {
	path := codexConfigPath()
	if path == "" {
		return fmt.Errorf("resolve ~/.codex/config.toml")
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		data = nil
	} else if err != nil {
		return err
	}
	config, err := parseCodexConfig(strings.NewReader(string(data)), codexConfig{Features: map[string]bool{}, Present: map[string]bool{}, Trust: map[string]string{}})
	if err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	feature := "codex_hooks"
	if status := InspectCodex(); status.Feature != "" {
		feature = status.Feature
	} else if config.Present["hooks"] {
		feature = "hooks"
	}
	updated, changed := setCodexFeature(string(data), feature, true)
	if !changed {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(updated), 0600)
}

func setCodexFeature(data, feature string, enabled bool) (string, bool) {
	value := "false"
	if enabled {
		value = "true"
	}
	lines := strings.SplitAfter(data, "\n")
	featuresStart := -1
	for i, raw := range lines {
		line := strings.TrimSpace(stripTOMLComment(strings.TrimSuffix(raw, "\n")))
		if line == "[features]" {
			featuresStart = i
			continue
		}
		if featuresStart >= 0 && strings.HasPrefix(line, "[") && line != "[features]" {
			lines = append(lines[:i], append([]string{feature + " = " + value + "\n"}, lines[i:]...)...)
			return strings.Join(lines, ""), true
		}
		if featuresStart >= 0 {
			key, _, ok := strings.Cut(line, "=")
			if ok && strings.TrimSpace(key) == feature {
				indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
				comment := ""
				if index := strings.Index(raw, "#"); index >= 0 {
					comment = " " + strings.TrimSpace(raw[index:])
				}
				newline := ""
				if strings.HasSuffix(raw, "\n") {
					newline = "\n"
				}
				lines[i] = indent + feature + " = " + value + comment + newline
				return strings.Join(lines, ""), true
			}
		}
	}
	if featuresStart >= 0 {
		lines = append(lines, feature+" = "+value+"\n")
		return strings.Join(lines, ""), true
	}
	separator := ""
	if data != "" && !strings.HasSuffix(data, "\n") {
		separator = "\n"
	}
	return data + separator + "\n[features]\n" + feature + " = " + value + "\n", true
}

func codexHooksPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".codex", "hooks.json")
}

func InstallCodexHooks() error {
	binary, err := hookExecutable()
	if err != nil {
		return fmt.Errorf("resolve hook executable: %w", err)
	}
	implementation := codexadapter.Adapter{}
	if err := implementation.Descriptor().Validate(); err != nil {
		return fmt.Errorf("Codex adapter descriptor: %w", err)
	}
	if err := implementation.Capabilities().Validate(); err != nil {
		return fmt.Errorf("Codex adapter capabilities: %w", err)
	}
	path := codexHooksPath()
	if path == "" {
		return fmt.Errorf("resolve Codex hooks path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	settings, err := readSettings(path)
	if err != nil {
		return fmt.Errorf("read Codex hooks: %w", err)
	}
	if err := backupCodexHooks(path); err != nil {
		return fmt.Errorf("backup Codex hooks: %w", err)
	}
	hooks, _ := settings["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = make(map[string]interface{})
	}
	for event, ours := range codexHooks {
		// Copy the template so repeated installations never mutate it.
		encoded, _ := json.Marshal(ours)
		var entry map[string]interface{}
		_ = json.Unmarshal(encoded, &entry)
		for _, value := range entry["hooks"].([]interface{}) {
			hook := value.(map[string]interface{})
			hook["command"] = shellQuote(binary) + strings.TrimPrefix(hook["command"].(string), "secuarden")
		}
		list := getMatcherList(hooks[event])
		list = removeSecuardenEntries(list)
		list = append(list, entry)
		hooks[event] = list
	}
	settings["hooks"] = hooks
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}

func RemoveCodexHooks() error {
	path := codexHooksPath()
	settings, err := readSettings(path)
	if err != nil {
		return fmt.Errorf("read Codex hooks: %w", err)
	}
	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		return nil
	}
	for event := range codexHooks {
		list := removeSecuardenEntries(getMatcherList(hooks[event]))
		if len(list) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = list
		}
	}
	if len(hooks) == 0 {
		delete(settings, "hooks")
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}

func CodexHooksInstalled() bool {
	settings, err := readSettings(codexHooksPath())
	if err != nil {
		return false
	}
	hooks, _ := settings["hooks"].(map[string]interface{})
	for event := range codexHooks {
		for _, entry := range getMatcherList(hooks[event]) {
			if isSecuardenEntry(entry) {
				return true
			}
		}
	}
	return false
}

func backupCodexHooks(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".secuarden", "backups")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	name := "codex-hooks.json." + time.Now().UTC().Format("20060102T150405Z")
	return os.WriteFile(filepath.Join(dir, name), data, 0600)
}

// disabledCodexHooks checks only state IDs belonging to currently installed
// Secuarden handlers. Stale entries and other tools' disabled hooks are ignored.
func disabledCodexHooks(config codexConfig) []string {
	settings, err := readSettings(codexHooksPath())
	if err != nil {
		return nil
	}
	hooks, _ := settings["hooks"].(map[string]interface{})
	names := map[string]string{"SessionStart": "session_start", "SessionEnd": "session_end", "PreToolUse": "pre_tool_use", "PostToolUse": "post_tool_use", "PermissionRequest": "permission_request", "UserPromptSubmit": "user_prompt_submit", "Stop": "stop"}
	disabled := []string{}
	for event, name := range names {
		for i, entry := range getMatcherList(hooks[event]) {
			group, ok := entry.(map[string]interface{})
			if !ok {
				continue
			}
			handlers, _ := group["hooks"].([]interface{})
			for j, handler := range handlers {
				single := map[string]interface{}{"hooks": []interface{}{handler}}
				if !isSecuardenEntry(single) {
					continue
				}
				id := fmt.Sprintf("%s:%s:%d:%d", codexHooksPath(), name, i, j)
				if enabled, present := config.HookEnabled[id]; present && !enabled {
					disabled = append(disabled, event)
				}
			}
		}
	}
	sort.Strings(disabled)
	return disabled
}
