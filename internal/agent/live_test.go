package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveRequiresAllHooksAndRejectsDisabled(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := claudeSettingsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{}`, `{"hooks":{"SessionStart":[{"hooks":[{"command":"secuarden hook session-start"}]}]}}`, `{"disableAllHooks":true}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if LiveHooksConfigured("claude-code") {
			t.Fatal("incomplete/disabled hooks accepted")
		}
	}
}

func TestLiveExecutableDependencies(t *testing.T) {
	for _, name := range []string{"claude-code", "codex"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			dir := filepath.Join(t.TempDir(), "space and 'quote")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(dir, "secuarden")
			write := func(content string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(binary, []byte(content), mode); err != nil {
					t.Fatal(err)
				}
			}
			write("#!/bin/sh\nexit 0\n", 0700)
			old := installedExecutable
			installedExecutable = func() (string, error) { return binary, nil }
			t.Cleanup(func() { installedExecutable = old })
			if name == "codex" {
				if err := InstallCodexHooks(); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(codexConfigPath(), []byte("[features]\nhooks = true\n"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.MkdirAll(filepath.Dir(claudeSettingsPath()), 0700); err != nil {
					t.Fatal(err)
				}
				if err := InstallHooks(); err != nil {
					t.Fatal(err)
				}
			}
			before, err := HookFingerprint(name)
			if err != nil {
				t.Fatal(err)
			}
			if !LiveHooksConfigured(name) {
				t.Fatal("valid dependency rejected")
			}
			write("#!/bin/sh\nexit 1\n", 0700)
			after, err := HookFingerprint(name)
			if err != nil || before == after {
				t.Fatalf("binary replacement not detected: %v", err)
			}
			if err := os.Chmod(binary, 0600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateLiveHooks(name); err == nil || !strings.Contains(err.Error(), "configured command not executable") {
				t.Fatal(err)
			}
			if err := os.Remove(binary); err != nil {
				t.Fatal(err)
			}
			if err := ValidateLiveHooks(name); err == nil || !strings.Contains(err.Error(), "configured command missing") {
				t.Fatal(err)
			}
			if _, err := HookFingerprint(name); err == nil {
				t.Fatal("missing dependency fingerprint accepted")
			}
			if err := os.Symlink(filepath.Join(dir, "deleted-target"), binary); err != nil {
				t.Fatal(err)
			}
			if err := ValidateLiveHooks(name); err == nil || !strings.Contains(err.Error(), "configured command missing") {
				t.Fatal(err)
			}
		})
	}
}
