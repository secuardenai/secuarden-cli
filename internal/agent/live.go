package agent

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// HookFingerprint hashes configuration and resolved executable bytes without retaining contents.
// Whole-file hashing deliberately invalidates conservatively on settings edits.
func HookFingerprint(name string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	paths := []string{filepath.Join(home, ".claude", "settings.json")}
	if name == "codex" {
		paths = []string{codexHooksPath(), codexConfigPath()}
	}
	hash := sha256.New()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(hash, "%d:", len(data))
		hash.Write(data)
	}
	dependencies, err := liveHookDependencies(name)
	if err != nil {
		return "", err
	}
	for _, path := range dependencies {
		file, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("configured command unavailable: %s: %w", path, err)
		}
		digest := sha256.New()
		_, err = io.Copy(digest, file)
		file.Close()
		if err != nil {
			return "", fmt.Errorf("read configured command: %w", err)
		}
		fmt.Fprintf(hash, "%d:%s:%x", len(path), path, digest.Sum(nil))
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// LiveHooksConfigured requires the lifecycle and both tool hooks used by the
// verifier, rather than accepting any one installed Secuarden hook.
func LiveHooksConfigured(name string) bool {
	return ValidateLiveHooks(name) == nil
}

// ValidateLiveHooks checks installed dependencies without executing configured
// commands. Runtime activation and actual delivery still require live evidence.
func ValidateLiveHooks(name string) error {
	_, err := liveHookDependencies(name)
	return err
}

func liveHookDependencies(name string) ([]string, error) {
	path := claudeSettingsPath()
	if name == "codex" {
		path = codexHooksPath()
	}
	settings, err := readSettings(path)
	if err != nil {
		return nil, fmt.Errorf("hook configuration unavailable: %w", err)
	}
	if disabled, _ := settings["disableAllHooks"].(bool); disabled {
		return nil, fmt.Errorf("hook configuration disabled")
	}
	hooks, _ := settings["hooks"].(map[string]interface{})
	dependencies := map[string]bool{}
	for _, event := range []string{"SessionStart", "PreToolUse", "PostToolUse"} {
		found := false
		for _, entry := range getMatcherList(hooks[event]) {
			matcher, _ := entry.(map[string]interface{})
			entries, _ := matcher["hooks"].([]interface{})
			for _, value := range entries {
				hook, _ := value.(map[string]interface{})
				// Recognize each command individually, including legacy args-style hooks.
				if !isSecuardenEntry(map[string]interface{}{"hooks": []interface{}{hook}}) {
					continue
				}
				found = true
				command, _ := hook["command"].(string)
				executable := configuredExecutable(command)
				resolved, err := exec.LookPath(executable)
				if err != nil {
					if errors.Is(err, os.ErrNotExist) || (!strings.ContainsRune(executable, os.PathSeparator) && errors.Is(err, exec.ErrNotFound)) {
						return nil, fmt.Errorf("configured command missing: %s (%s); install secuarden at a persistent path and run hooks refresh", executable, event)
					}
					return nil, fmt.Errorf("configured command not executable: %s (%s): %w", executable, event, err)
				}
				info, err := os.Stat(resolved)
				if err != nil {
					return nil, fmt.Errorf("configured command unavailable: %s: %w", executable, err)
				}
				if !info.Mode().IsRegular() {
					return nil, fmt.Errorf("configured command not executable: %s is not a regular file", executable)
				}
				resolved, err = filepath.EvalSymlinks(resolved)
				if err != nil {
					return nil, fmt.Errorf("configured command unavailable: %s: %w", executable, err)
				}
				dependencies[resolved] = true
			}
		}
		if !found {
			return nil, fmt.Errorf("hook configuration missing: %s", event)
		}
	}
	paths := make([]string, 0, len(dependencies))
	for path := range dependencies {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, nil
}

// Decode only the executable syntax emitted by our installers; never evaluate
// shell expansions or run a hook as a dependency check.
func configuredExecutable(command string) string {
	if index := strings.LastIndex(command, " hook "); index >= 0 {
		command = command[:index]
	}
	command = strings.Trim(command, "\"'")
	return strings.ReplaceAll(command, "'\\''", "'")
}
