package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/events"
)

func TestCodexLifecycleWithoutToolInvocation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mustSavePrivacy(t, "metadata_only")
	dir := t.TempDir()
	checkpointGit(t, dir, "init")
	checkpointGit(t, dir, "config", "user.email", "fixture@example.com")
	checkpointGit(t, dir, "config", "user.name", "Fixture")
	checkpointWrite(t, dir, "tracked.txt", "initial\n")
	checkpointGit(t, dir, "add", ".")
	checkpointGit(t, dir, "commit", "-m", "initial")
	db := openCaptureDB(t)
	defer db.Close()
	for i, step := range []struct{ hook, phase, want string }{
		{"SessionStart", "session-start", events.HookPhaseSessionStart},
		{"UserPromptSubmit", "user-prompt-submit", events.HookPhaseIntent},
		{"Stop", "stop", events.HookPhaseCheckpoint},
		{"SessionEnd", "session-end", events.HookPhaseSessionEnd},
	} {
		payload, _ := json.Marshal(map[string]interface{}{"session_id": "codex-lifecycle", "cwd": dir, "hook_event_name": step.hook, "prompt": "test lifecycle"})
		input, err := os.CreateTemp(t.TempDir(), "hook")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := input.Write(payload); err != nil {
			t.Fatal(err)
		}
		if _, err := input.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		old := os.Stdin
		os.Stdin = input
		err = handleWithParser(step.phase, "test", "codex", "openai", parseCodexInput)
		os.Stdin = old
		input.Close()
		if err != nil {
			t.Fatalf("%s: %v", step.hook, err)
		}
		envelope, err := db.ReadSessionEnvelope("codex-lifecycle")
		if err != nil {
			t.Fatal(err)
		}
		if len(envelope.Events) != i+1 {
			t.Fatal("event missing")
		}
		e := envelope.Events[i]
		if e.HookPhase != step.want || e.InvocationID != "" {
			t.Fatalf("event: %+v", e)
		}
		if step.hook != "UserPromptSubmit" && (e.RepositoryCheckpoint == nil || e.RepositoryCheckpoint.Status != "complete") {
			t.Fatalf("checkpoint: %+v", e.RepositoryCheckpoint)
		}
		if step.hook != "SessionEnd" && envelope.EndedAt != "" {
			t.Fatal("turn completion incorrectly ended session")
		}
		if step.hook == "SessionEnd" && envelope.EndedAt == "" {
			t.Fatal("session end missing")
		}
	}
	result, err := db.VerifyIntegrity()
	if err != nil || !result.Valid {
		t.Fatalf("integrity: %+v %v", result, err)
	}
}

func TestCodexPermissionRequestWithoutToolUseID(t *testing.T) {
	payload, _ := json.Marshal(map[string]interface{}{"session_id": "permission", "hook_event_name": "PermissionRequest", "cwd": filepath.Clean(t.TempDir()), "tool_name": "Bash", "tool_input": map[string]string{"command": "echo test"}})
	raw, err := parseCodexInput(payload)
	if err != nil {
		t.Fatal(err)
	}
	if raw.ToolUseID != "" {
		t.Fatal("must not invent invocation correlation")
	}
}
