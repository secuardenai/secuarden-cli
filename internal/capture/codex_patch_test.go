package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func TestCodexApplyPatchCapturePrivacy(t *testing.T) {
	t.Run("ordinary multi-file operations and rename", func(t *testing.T) {
		home := t.TempDir()
		cwd := t.TempDir()
		t.Setenv("HOME", home)
		mustSavePrivacy(t, "redacted_content")
		patch := "*** Begin Patch\n" +
			"*** Add File: add.txt\n+added\n" +
			"*** Update File: update.txt\n@@\n-old\n+new\n" +
			"*** Delete File: delete.txt\n" +
			"*** Update File: from.txt\n*** Move to: to.txt\n@@\n-old name\n+new name\n" +
			"*** End Patch"
		captureCodexPatch(t, "pre-tool-use", "PreToolUse", "ordinary", "call-1", cwd, patch, nil)
		db := openCaptureDB(t)
		got, err := db.QueryEvents(storage.EventFilter{SessionID: "ordinary", Limit: 10})
		if err != nil || len(got) != 1 {
			t.Fatalf("events=%d err=%v", len(got), err)
		}
		e := got[0]
		if e.InvocationID != "call-1" || e.Outcome != "pending" || e.ExecutionStatus != "not_started" {
			t.Fatalf("proposal correlation/status lost: %#v", e)
		}
		if len(e.AffectedFiles) != 5 || e.AffectedFiles[3].Operation != "move_source" || e.AffectedFiles[4].Operation != "move_destination" {
			t.Fatalf("affected files=%#v", e.AffectedFiles)
		}
		if e.Command != patch || e.IsSensitive {
			t.Fatalf("ordinary patch was not retained safely: %#v", e)
		}
		envelope, err := db.ReadSessionEnvelope("ordinary")
		if err != nil {
			t.Fatal(err)
		}
		if len(envelope.FilesEdited) != 0 {
			t.Fatalf("pre-tool proposal reported as applied: %#v", envelope.FilesEdited)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		captureCodexPatch(t, "post-tool-use", "PostToolUse", "ordinary", "call-1", cwd, patch, map[string]interface{}{"success": true, "output": "Done!"})
		db = openCaptureDB(t)
		defer db.Close()
		envelope, err = db.ReadSessionEnvelope("ordinary")
		if err != nil {
			t.Fatal(err)
		}
		if len(envelope.FilesEdited) != 5 || envelope.Events[1].InvocationID != "call-1" || envelope.Events[1].Outcome != "success" {
			t.Fatalf("completed multi-file patch evidence is inaccurate: %#v", envelope)
		}
	})

	t.Run("invalid body content is never persisted or exported", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		mustSavePrivacy(t, "redacted_content")
		marker := "UNPREFIXED_CAPTURE_MARKER_72c04f"
		patch := "*** Begin Patch\n*** Add File: safe.txt\n" + marker + "\n*** End Patch"
		captureCodexPatch(t, "post-tool-use", "PostToolUse", "invalid-body", "call-invalid-body", t.TempDir(), patch, map[string]interface{}{"output": "response " + marker})
		assertLimitedPatchContentAbsent(t, "invalid-body", marker)
	})

	t.Run("sensitive and credential paths suppress content", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		mustSavePrivacy(t, "redacted_content")
		secret := "DO_NOT_PERSIST_7f82d9"
		patch := "*** Begin Patch\n*** Add File: .env\n+TOKEN=" + secret + "\n*** Update File: config/credentials.json\n@@\n-old\n+" + secret + "\n*** End Patch"
		captureCodexPatch(t, "post-tool-use", "PostToolUse", "sensitive", "call-2", t.TempDir(), patch, map[string]interface{}{"output": "applied " + secret})
		assertCapturedSecretAbsent(t, "sensitive", secret, 2, true)
	})

	t.Run("mixed sensitivity suppresses the complete patch", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		mustSavePrivacy(t, "redacted_content")
		secret := "MIXED_SECRET_6b02d1"
		patch := "*** Begin Patch\n*** Update File: public.txt\n@@\n-old\n+public\n*** Update File: .env.local\n@@\n-old\n+" + secret + "\n*** End Patch"
		captureCodexPatch(t, "post-tool-use", "PostToolUse", "mixed", "call-3", t.TempDir(), patch, map[string]interface{}{"output": secret})
		assertCapturedSecretAbsent(t, "mixed", secret, 2, true)
	})

	t.Run("relative path classification uses cwd", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		mustSavePrivacy(t, "redacted_content")
		cwd := filepath.Join(t.TempDir(), ".ssh", "project")
		if err := os.MkdirAll(cwd, 0700); err != nil {
			t.Fatal(err)
		}
		secret := "RELATIVE_SECRET_945b17"
		patch := "*** Begin Patch\n*** Update File: notes.txt\n@@\n-old\n+" + secret + "\n*** End Patch"
		captureCodexPatch(t, "pre-tool-use", "PreToolUse", "relative", "call-4", cwd, patch, nil)
		assertCapturedSecretAbsent(t, "relative", secret, 1, true)
	})

	t.Run("malformed patch is limited evidence", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		mustSavePrivacy(t, "redacted_content")
		secret := "MALFORMED_SECRET_e192fe"
		patch := "*** Begin Patch\n*** Add File: .env\n+TOKEN=" + secret
		captureCodexPatch(t, "pre-tool-use", "PreToolUse", "malformed", "call-5", t.TempDir(), patch, nil)
		db := openCaptureDB(t)
		defer db.Close()
		got, err := db.QueryEvents(storage.EventFilter{SessionID: "malformed", Limit: 10})
		if err != nil || len(got) != 1 {
			t.Fatalf("events=%d err=%v", len(got), err)
		}
		e := got[0]
		if e.Command != "" || !e.IsSensitive || e.Completeness.State != "partial" || !containsString(e.Completeness.Reasons, "patch_parse_failed") {
			t.Fatalf("malformed patch not conservatively limited: %#v", e)
		}
		body, _ := json.Marshal(e)
		if strings.Contains(string(body), secret) {
			t.Fatal("malformed patch content entered persisted evidence")
		}
		logBody, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".secuarden", "error.log"))
		if strings.Contains(string(logBody), secret) {
			t.Fatal("malformed patch content entered error logs")
		}
	})

	t.Run("metadata only retains no patch content", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		mustSavePrivacy(t, "metadata_only")
		secret := "sk-abcdefghijklmnopqrstuvwxyz123456"
		patch := "*** Begin Patch\n*** Add File: safe.txt\n+API_KEY=" + secret + "\n*** End Patch"
		captureCodexPatch(t, "post-tool-use", "PostToolUse", "metadata", "call-6", t.TempDir(), patch, map[string]interface{}{"output": secret})
		assertCapturedSecretAbsent(t, "metadata", secret, 1, false)
	})

	t.Run("redacted content scrubs permitted patch", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		mustSavePrivacy(t, "redacted_content")
		secret := "sk-abcdefghijklmnopqrstuvwxyz123456"
		patch := "*** Begin Patch\n*** Add File: safe.txt\n+API_KEY=" + secret + "\n*** End Patch"
		captureCodexPatch(t, "post-tool-use", "PostToolUse", "redacted", "call-7", t.TempDir(), patch, map[string]interface{}{"output": "wrote " + secret})
		db := openCaptureDB(t)
		defer db.Close()
		got, err := db.QueryEvents(storage.EventFilter{SessionID: "redacted", Limit: 10})
		if err != nil || len(got) != 1 {
			t.Fatalf("events=%d err=%v", len(got), err)
		}
		if strings.Contains(got[0].Command+got[0].CommandOutputPreview, secret) || !strings.Contains(got[0].Command, "[REDACTED:env_secret]") {
			t.Fatalf("permitted content was not redacted: %#v", got[0])
		}
	})
}

func captureCodexPatch(t *testing.T, phase, hook, session, invocation, cwd, patch string, response map[string]interface{}) {
	t.Helper()
	payload := map[string]interface{}{
		"session_id": session, "cwd": cwd, "hook_event_name": hook,
		"tool_name": "apply_patch", "tool_use_id": invocation,
		"tool_input": map[string]interface{}{"command": patch},
	}
	if response != nil {
		payload["tool_response"] = response
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.CreateTemp(t.TempDir(), "codex-hook-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = input
	err = handleWithParser(phase, "test", "codex", "openai", parseCodexInput)
	os.Stdin = old
	_ = input.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func mustSavePrivacy(t *testing.T, mode string) {
	t.Helper()
	if err := config.Save(&config.Config{PrivacyMode: mode, CaptureScope: config.CaptureScopeAll}); err != nil {
		t.Fatal(err)
	}
}

func openCaptureDB(t *testing.T) *storage.DB {
	t.Helper()
	path, err := storage.DefaultDBPath()
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func assertCapturedSecretAbsent(t *testing.T, session, secret string, affected int, sensitive bool) {
	t.Helper()
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		t.Fatal(err)
	}
	db := openCaptureDB(t)
	got, err := db.QueryEvents(storage.EventFilter{SessionID: session, Limit: 10})
	if err != nil || len(got) != 1 {
		t.Fatalf("events=%d err=%v", len(got), err)
	}
	if got[0].IsSensitive != sensitive || len(got[0].AffectedFiles) != affected || got[0].Command != "" || got[0].CommandOutputPreview != "" {
		t.Fatalf("unsafe captured event: %#v", got[0])
	}
	envelope, err := db.ReadSessionEnvelope(session)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), secret) {
		t.Fatal("secret entered exported evidence")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dbPath, dbPath + "-wal"} {
		raw, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(raw), secret) {
			t.Fatalf("secret entered SQLite persistence at %s", filepath.Base(path))
		}
	}
}

func assertLimitedPatchContentAbsent(t *testing.T, session, marker string) {
	t.Helper()
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		t.Fatal(err)
	}
	db := openCaptureDB(t)
	got, err := db.QueryEvents(storage.EventFilter{SessionID: session, Limit: 10})
	if err != nil || len(got) != 1 {
		t.Fatalf("events=%d err=%v", len(got), err)
	}
	e := got[0]
	if e.Command != "" || e.CommandOutputPreview != "" || !e.IsSensitive || e.Completeness.State != "partial" || !containsString(e.Completeness.Reasons, "patch_parse_failed") {
		t.Fatalf("invalid patch body not conservatively limited: %#v", e)
	}
	envelope, err := db.ReadSessionEnvelope(session)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), marker) {
		t.Fatal("invalid patch content entered exported evidence")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dbPath, dbPath + "-wal"} {
		raw, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(raw), marker) {
			t.Fatalf("invalid patch content entered SQLite persistence at %s", filepath.Base(path))
		}
	}
	logBody, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".secuarden", "error.log"))
	if strings.Contains(string(logBody), marker) {
		t.Fatal("invalid patch content entered error logs")
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
