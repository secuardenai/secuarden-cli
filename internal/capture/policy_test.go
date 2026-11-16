package capture

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/policy"
)

func TestPolicyDenialPrecedesCaptureFailures(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cwd := t.TempDir()
	if _, _, err := policy.Import("../../fixtures/policy/flask-security.json"); err != nil {
		t.Fatal(err)
	}
	// Corrupt capture configuration must not bypass enforcement.
	store, _ := policy.StorePath()
	if err := os.WriteFile(filepath.Join(filepath.Dir(store), "config.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	source := "@app.route('/private')\n@login_required\ndef private():\n    return 'hello'\n"
	path := filepath.Join(cwd, "app.py")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"pre-tool-use", "permission-request"} {
		t.Run(phase, func(t *testing.T) {
			data, _ := json.Marshal(map[string]any{"session_id": "policy-test", "tool_use_id": "edit-1", "cwd": cwd, "tool_name": "apply_patch", "tool_input": map[string]any{"command": "*** Begin Patch\n*** Update File: app.py\n@@\n-@login_required\n*** End Patch"}})
			input, err := os.CreateTemp(t.TempDir(), "input")
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err = input.Write(data); err != nil {
				t.Fatal(err)
			}
			if _, err = input.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			output, err := os.CreateTemp(t.TempDir(), "output")
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			oldIn, oldOut := os.Stdin, os.Stdout
			os.Stdin, os.Stdout = input, output
			defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()
			HandleCodexHookEvent(phase, "test")
			if _, err = output.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			result, err := io.ReadAll(output)
			if err != nil {
				t.Fatal(err)
			}
			var response map[string]any
			if json.Unmarshal(result, &response) != nil {
				t.Fatalf("invalid response %s", result)
			}
			if !strings.Contains(string(result), `"deny"`) || !strings.Contains(string(result), "protect-flask-route-security") {
				t.Fatalf("missing denial: %s", result)
			}
			unchanged, _ := os.ReadFile(path)
			if string(unchanged) != source {
				t.Fatal("source changed")
			}
		})
	}
}
