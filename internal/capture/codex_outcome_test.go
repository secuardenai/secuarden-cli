package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func TestCodexPostOutcomeDoesNotAssumeSuccess(t *testing.T) {
	tests := []struct {
		name        string
		response    interface{}
		setResponse bool
	}{
		{name: "failed scalar", response: "tool failed", setResponse: true},
		{name: "missing response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			mustSavePrivacy(t, "redacted_content")
			captureCodexTool(t, "post-tool-use", "PostToolUse", "outcome", "call-outcome", "Bash",
				map[string]interface{}{"command": "false"}, test.response, test.setResponse)

			db := openCaptureDB(t)
			defer db.Close()
			got, err := db.QueryEvents(storage.EventFilter{SessionID: "outcome", Limit: 10})
			if err != nil || len(got) != 1 {
				t.Fatalf("events=%d err=%v", len(got), err)
			}
			e := got[0]
			if e.Outcome != "unknown" || e.ExecutionStatus != "unknown" || e.ResultStatus != "unknown" {
				t.Fatalf("unsupported result became certain: outcome=%q execution=%q result=%q", e.Outcome, e.ExecutionStatus, e.ResultStatus)
			}
			if e.InvocationID != "call-outcome" || e.PermissionStatus != "unknown" || e.Completeness.State != "partial" || !containsString(e.Completeness.Reasons, "adapter_field_unavailable") {
				t.Fatalf("unknown result evidence is incomplete: %#v", e)
			}
		})
	}
}

func TestCodexPostOutcomeSupportedShapes(t *testing.T) {
	tests := []struct {
		name, tool, result, outcome, execution string
		response                               interface{}
		exitCode                               *int
	}{
		{name: "successful object", tool: "Bash", response: map[string]interface{}{"exit_code": 0, "output": "done"}, result: "success", outcome: "success", execution: "completed", exitCode: outcomeInt(0)},
		{name: "failed object", tool: "Bash", response: map[string]interface{}{"exit_code": 9, "output": "failed"}, result: "error", outcome: "error", execution: "failed", exitCode: outcomeInt(9)},
		{name: "MCP error", tool: "mcp__docs__lookup", response: map[string]interface{}{"isError": true, "content": []interface{}{map[string]interface{}{"type": "text", "text": "denied"}}}, result: "error", outcome: "error", execution: "failed"},
		{name: "successful array", tool: "Bash", response: []interface{}{map[string]interface{}{"exit_code": 0}, map[string]interface{}{"status": "completed"}}, result: "success", outcome: "success", execution: "completed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			mustSavePrivacy(t, "redacted_content")
			captureCodexTool(t, "post-tool-use", "PostToolUse", "supported", "call-supported", test.tool,
				map[string]interface{}{"command": "tool command"}, test.response, true)
			db := openCaptureDB(t)
			defer db.Close()
			got, err := db.QueryEvents(storage.EventFilter{SessionID: "supported", Limit: 10})
			if err != nil || len(got) != 1 {
				t.Fatalf("events=%d err=%v", len(got), err)
			}
			e := got[0]
			if e.Outcome != test.outcome || e.ExecutionStatus != test.execution || e.ResultStatus != test.result {
				t.Fatalf("incorrect normalized outcome: %#v", e)
			}
			if e.PermissionStatus != "unknown" {
				t.Fatalf("execution inferred permission approval: %#v", e)
			}
			if test.exitCode != nil && (e.ExitCode == nil || *e.ExitCode != *test.exitCode) {
				t.Fatalf("exit code=%v, want %d", e.ExitCode, *test.exitCode)
			}
		})
	}
}

func TestCodexPreToolProposalIsPending(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mustSavePrivacy(t, "redacted_content")
	captureCodexTool(t, "pre-tool-use", "PreToolUse", "proposal", "call-proposal", "Bash",
		map[string]interface{}{"command": "echo hi"}, nil, false)
	db := openCaptureDB(t)
	defer db.Close()
	got, err := db.QueryEvents(storage.EventFilter{SessionID: "proposal", Limit: 10})
	if err != nil || len(got) != 1 {
		t.Fatalf("events=%d err=%v", len(got), err)
	}
	if got[0].Outcome != "pending" || got[0].ExecutionStatus != "not_started" || got[0].PermissionStatus != "unknown" {
		t.Fatalf("proposal status=%#v", got[0])
	}
}

func TestFailedAndUnknownCodexPatchesAreNotAppliedEvidence(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mustSavePrivacy(t, "redacted_content")
	patch := "*** Begin Patch\n*** Add File: result.txt\n+content\n*** End Patch"
	input := map[string]interface{}{"command": patch}
	captureCodexTool(t, "post-tool-use", "PostToolUse", "unapplied", "call-failed", "apply_patch", input,
		map[string]interface{}{"exit_code": 1, "output": "not applied"}, true)
	captureCodexTool(t, "post-tool-use", "PostToolUse", "unapplied", "call-unknown", "apply_patch", input, nil, false)
	db := openCaptureDB(t)
	defer db.Close()
	envelope, err := db.ReadSessionEnvelope("unapplied")
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope.FilesEdited) != 0 {
		t.Fatalf("unconfirmed patches exported as applied: %#v", envelope.FilesEdited)
	}
	records, err := db.ListWriteProvenance(time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("unconfirmed patches entered provenance: %#v", records)
	}
	activity, err := db.GetSessionInvestigation("unapplied")
	if err != nil {
		t.Fatal(err)
	}
	if len(activity.FilesChanged) != 0 {
		t.Fatalf("unconfirmed patches entered file metrics: %#v", activity.FilesChanged)
	}
}

func TestCodexResponsePrivacyModes(t *testing.T) {
	for _, mode := range []string{"redacted_content", "metadata_only"} {
		t.Run(mode, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			mustSavePrivacy(t, mode)
			marker := "sk-abcdefghijklmnopqrstuvwxyz123456"
			captureCodexTool(t, "post-tool-use", "PostToolUse", "privacy", "call-privacy", "Bash",
				map[string]interface{}{"command": "printf safe"}, map[string]interface{}{"exit_code": 1, "error": marker}, true)
			dbPath, err := storage.DefaultDBPath()
			if err != nil {
				t.Fatal(err)
			}
			db := openCaptureDB(t)
			got, err := db.QueryEvents(storage.EventFilter{SessionID: "privacy", Limit: 10})
			if err != nil || len(got) != 1 {
				t.Fatalf("events=%d err=%v", len(got), err)
			}
			if got[0].Outcome != "error" || strings.Contains(got[0].CommandOutputPreview, marker) {
				t.Fatalf("response outcome/privacy=%#v", got[0])
			}
			if mode == "metadata_only" && (got[0].Command != "" || got[0].CommandOutputPreview != "") {
				t.Fatalf("metadata-only retained content: %#v", got[0])
			}
			envelope, err := db.ReadSessionEnvelope("privacy")
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(envelope)
			_ = db.Close()
			if strings.Contains(string(encoded), marker) {
				t.Fatal("marker entered exported envelope")
			}
			for _, path := range []string{dbPath, dbPath + "-wal"} {
				raw, readErr := os.ReadFile(path)
				if readErr == nil && strings.Contains(string(raw), marker) {
					t.Fatalf("marker entered SQLite at %s", filepath.Base(path))
				}
			}
			logBody, _ := os.ReadFile(filepath.Join(home, ".secuarden", "error.log"))
			if strings.Contains(string(logBody), marker) {
				t.Fatal("marker entered error logs")
			}
		})
	}
}

func outcomeInt(value int) *int { return &value }

func captureCodexTool(t *testing.T, phase, hook, session, invocation, tool string, input map[string]interface{}, response interface{}, setResponse bool) {
	t.Helper()
	payload := map[string]interface{}{
		"session_id": session, "cwd": t.TempDir(), "hook_event_name": hook,
		"tool_name": tool, "tool_use_id": invocation, "tool_input": input,
	}
	if setResponse {
		payload["tool_response"] = response
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "codex-outcome-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = file
	err = handleWithParser(phase, "test", "codex", "openai", parseCodexInput)
	os.Stdin = old
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
}
