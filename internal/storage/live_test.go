package storage

import (
	"github.com/secuardenai/secuarden-cli/internal/events"
	"testing"
)

func TestLivePersistedMetadata(t *testing.T) {
	db, _ := tempDB(t)
	defer db.Close()
	if err := db.EnsureSession("s", "codex", "/repo"); err != nil {
		t.Fatal(err)
	}
	mark, err := db.LiveWatermark()
	if err != nil {
		t.Fatal(err)
	}
	e := &events.Event{ID: "e", SessionID: "s", Timestamp: "2026-10-17T00:00:00Z", Source: "secuarden-cli", AgentName: "codex", HookPhase: "pre", ActionType: "command_exec", ToolName: "exec_command", InvocationID: "call", WorkingDirectory: "/repo", PrivacyMode: "metadata_only"}
	if err := db.WriteEvent(e); err != nil {
		t.Fatal(err)
	}
	rows, old, failures, err := db.LiveEvidence(mark, "s", "codex")
	if err != nil || len(rows) != 1 || old || failures != 0 {
		t.Fatalf("%v %v %d %v", rows, old, failures, err)
	}
	newMark, _ := db.LiveWatermark()
	_, old, _, err = db.LiveEvidence(newMark, "s", "codex")
	if err != nil || !old {
		t.Fatal("old events accepted")
	}
	rows, _, _, err = db.LiveEvidence(mark, "other", "codex")
	if err != nil || len(rows) != 0 {
		t.Fatal("unrelated session accepted")
	}
	if err := db.RecordCaptureFailure("s", "post", "event_persistence_rejected"); err != nil {
		t.Fatal(err)
	}
	_, _, failures, err = db.LiveEvidence(mark, "s", "codex")
	if err != nil || failures != 1 {
		t.Fatal("missing failure")
	}
	if err := db.WriteLiveState("live_test", map[string]string{"stage": "pending"}); err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	ok, err := db.ReadLiveState("live_test", &result)
	if err != nil || !ok || result["stage"] != "pending" {
		t.Fatal(result, err)
	}
	db.Close()
	if _, _, _, err := db.LiveEvidence(mark, "s", "codex"); err == nil {
		t.Fatal("closed database accepted")
	}
}
