package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAbsoluteHookExecutableWithoutPATH(t *testing.T) {
	home := t.TempDir()
	patchHome(t, home)
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "space and 'quote")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "secuarden")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s' \"$*\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	installedExecutable = func() (string, error) { return binary, nil }
	for _, install := range []func() error{InstallHooks, InstallCodexHooks} {
		if err := install(); err != nil {
			t.Fatal(err)
		}
		if err := install(); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{claudeSettingsPath(), codexHooksPath()} {
		settings, err := readSettings(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range settings["hooks"].(map[string]interface{}) {
			list := getMatcherList(value)
			if len(list) != 1 || !isSecuardenEntry(list[0]) {
				t.Fatal("absolute hook detection or idempotency failed")
			}
			entry := list[0].(map[string]interface{})
			for _, value := range entry["hooks"].([]interface{}) {
				command := value.(map[string]interface{})["command"].(string)
				if !strings.HasPrefix(command, shellQuote(binary)) {
					t.Fatal("hook missing absolute path")
				}
				run := exec.Command("/bin/sh", "-c", command)
				run.Env = []string{"PATH=/usr/bin:/bin"}
				output, err := run.CombinedOutput()
				if err != nil || !strings.HasPrefix(string(output), "hook ") {
					t.Fatalf("quoted hook failed: %v %s", err, output)
				}
			}
		}
	}
}
