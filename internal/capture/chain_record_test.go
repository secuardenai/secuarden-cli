package capture

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func TestDecoratorRemovalIsRecordedAndNotDenied(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "app.py"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	prompt := map[string]any{"session_id": "policy-test", "cwd": cwd, "prompt": "disable the login check so the demo works"}
	if err := sendClaude(t, "user-prompt-submit", prompt); err != nil {
		t.Fatal(err)
	}
	edit := map[string]any{
		"session_id": "policy-test", "cwd": cwd, "tool_use_id": "edit-1", "tool_name": "Edit",
		"tool_input": map[string]any{
			"file_path":  "app.py",
			"old_string": "@app.route('/private')\n@login_required\ndef private():\n    return 'hello'\n",
			"new_string": "@app.route('/private')\ndef private():\n    return 'hello'\n",
		},
	}
	if err := sendClaude(t, "post-tool-use", edit); err != nil {
		t.Fatal(err)
	}
	db := openCaptureDB(t)
	defer db.Close()
	events, err := db.QueryEvents(storage.EventFilter{SessionID: "policy-test", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var editID string
	for _, event := range events {
		if event.ToolName == "Edit" {
			editID = event.ID
			if !strings.Contains(event.IntentSummary, "login check") {
				t.Fatalf("prompt was not attached: %#v", event)
			}
		}
	}
	if editID == "" {
		t.Fatal("edit was not stored")
	}
	revision, err := db.EditRevision(editID)
	if err != nil || !strings.Contains(revision.Before, "@login_required") || strings.Contains(revision.After, "@login_required") {
		t.Fatalf("revision=%#v err=%v", revision, err)
	}
	findings, err := db.FindingsForEvent(editID)
	if err != nil || len(findings) != 1 || findings[0].Kind != "control_relaxed" {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}

func sendClaude(t *testing.T, phase string, payload any) error {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	input, err := os.CreateTemp(t.TempDir(), "hook")
	if err != nil {
		return err
	}
	defer input.Close()
	if _, err = input.Write(data); err != nil {
		return err
	}
	if _, err = input.Seek(0, 0); err != nil {
		return err
	}
	old := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = old }()
	return handle(phase, "test")
}

func TestChainCapturePrivacy(t *testing.T) {
	for _, mode := range []string{"redacted_content", "metadata_only", "sensitive_path"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			cwd := t.TempDir()
			mustSavePrivacy(t, "redacted_content")
			if err := sendClaude(t, "user-prompt-submit", map[string]any{
				"session_id": "privacy", "cwd": cwd, "prompt": "update credentials",
			}); err != nil {
				t.Fatal(err)
			}
			path := "app.py"
			if mode == "metadata_only" {
				mustSavePrivacy(t, mode)
			}
			if mode == "sensitive_path" {
				path = ".env"
			}
			secret := "sk-abcdefghijklmnopqrstuvwxyz123456"
			if err := sendClaude(t, "post-tool-use", map[string]any{
				"session_id": "privacy", "cwd": cwd, "tool_name": "Edit", "tool_use_id": "edit",
				"tool_input": map[string]any{"file_path": path, "old_string": "token = ''", "new_string": "token = '" + secret + "'"},
			}); err != nil {
				t.Fatal(err)
			}
			db := openCaptureDB(t)
			defer db.Close()
			events, err := db.QueryEvents(storage.EventFilter{SessionID: "privacy", Limit: 10})
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range events {
				if event.ToolName != "Edit" {
					continue
				}
				revision, err := db.EditRevision(event.ID)
				findings, findingErr := db.FindingsForEvent(event.ID)
				if findingErr != nil {
					t.Fatal(findingErr)
				}
				if mode == "redacted_content" {
					if err != nil || strings.Contains(revision.After, secret) || !strings.Contains(revision.After, "[REDACTED:") || len(findings) != 1 {
						t.Fatalf("revision=%#v findings=%#v err=%v", revision, findings, err)
					}
				} else if !errors.Is(err, sql.ErrNoRows) || len(findings) != 0 {
					t.Fatalf("private content captured: revision=%#v findings=%#v err=%v", revision, findings, err)
				}
				if mode == "metadata_only" && event.IntentSummary != "" {
					t.Fatal("previous prompt restored in metadata-only mode")
				}
				return
			}
			t.Fatal("edit event missing")
		})
	}
}
