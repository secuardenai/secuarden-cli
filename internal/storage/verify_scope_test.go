package storage

import (
	"github.com/secuardenai/secuarden-cli/internal/events"
	"testing"
)

func TestVerifyIntegritySelectionKeepsCompleteChains(t *testing.T) {
	db, _ := tempDB(t)
	seedIntegrityChain(t, db)
	if err := db.EnsureSession("other", "codex", "/tmp/other"); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteEvent(&events.Event{ID: "other-event", SessionID: "other", Sequence: 1, AgentName: "codex", WorkingDirectory: "/tmp/other"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`UPDATE events SET command='changed' WHERE session_id='other'`); err != nil {
		t.Fatal(err)
	}
	// Working directories within the selected chain may differ; do not filter events by path.
	selected, err := db.VerifyIntegrityForSessions([]string{"sess-chain"})
	if err != nil || !selected.Valid || selected.EventsChecked != 2 || selected.SessionsChecked != 1 {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
	all, err := db.VerifyIntegrity()
	if err != nil || all.Valid || all.EventsChecked != 3 {
		t.Fatalf("all=%+v err=%v", all, err)
	}
	if len(all.Findings) != 1 || all.Findings[0].Kind != "event_hash_mismatch" || all.Findings[0].SessionID != "other" {
		t.Fatalf("findings=%+v", all.Findings)
	}
	for _, ids := range [][]string{nil, {}, {"missing"}} {
		empty, err := db.VerifyIntegrityForSessions(ids)
		if err != nil || empty.EventsChecked != 0 || empty.SessionsChecked != 0 {
			t.Fatalf("empty=%+v err=%v", empty, err)
		}
	}
}

func TestVerifyIntegrityFindingKinds(t *testing.T) {
	tests := []struct{ name, mutation, kind string }{
		{"chain", `UPDATE events SET previous_event_hash='wrong' WHERE sequence=2`, "broken_chain"},
		{"session", `UPDATE sessions SET agent_name='changed'`, "session_hash_mismatch"},
		{"legacy event", `UPDATE events SET event_hash=NULL WHERE sequence=2`, "legacy_event"},
		{"legacy session", `UPDATE sessions SET session_hash=NULL`, "legacy_session"},
		{"metadata", `UPDATE events SET repository_checkpoint='{}' WHERE sequence=2`, "unprotected_metadata"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, _ := tempDB(t)
			seedIntegrityChain(t, db)
			if _, err := db.db.Exec(test.mutation); err != nil {
				t.Fatal(err)
			}
			result, err := db.VerifyIntegrityForSessions([]string{"sess-chain"})
			if err != nil || result.Valid {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			for _, f := range result.Findings {
				if f.Kind == test.kind {
					return
				}
			}
			t.Fatalf("missing %s in %+v", test.kind, result.Findings)
		})
	}
}
