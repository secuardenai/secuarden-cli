package storage

import (
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/events"
	"github.com/secuardenai/secuarden-cli/internal/repository"
)

func TestCheckpointIntegrityAndConcurrentCapture(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.EnsureSession("checkpoint", "claude-code", "/repo"); err != nil {
		t.Fatal(err)
	}
	makeEvent := func(id string) *events.Event {
		return &events.Event{ID: id, SessionID: "checkpoint", Timestamp: "2026-09-01T00:00:00Z", Source: "secuarden-cli", AgentName: "claude-code", HookPhase: "post", ActionType: "file_write", RepositoryCheckpoint: &repository.Checkpoint{Kind: "post", Status: "complete", Reasons: []string{}, Files: []repository.FileState{{Path: "a", Attribution: "agent_associated"}}}}
	}
	first := makeEvent("first")
	if err := db.WriteEvent(first); err != nil {
		t.Fatal(err)
	}
	second := makeEvent("second") // captured concurrently against the same predecessor
	if err := db.WriteEvent(second); err != nil {
		t.Fatal(err)
	}
	if second.RepositoryCheckpoint.Status != "partial" || second.RepositoryCheckpoint.Files[0].Attribution != "human_or_unattributed" {
		t.Fatal("concurrent capture retained attribution")
	}
	envelope, err := db.ReadSessionEnvelope("checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(envelope.Events[0].EventHash, "v5:") {
		t.Fatal("checkpoint is not integrity bound")
	}

	result, err := db.VerifyIntegrity()
	if err != nil || !result.Valid {
		t.Fatalf("before tamper: %+v %v", result, err)
	}
	if _, err := db.db.Exec(`UPDATE events SET repository_checkpoint=replace(repository_checkpoint,'agent_associated','pre_existing') WHERE id='first'`); err != nil {
		t.Fatal(err)
	}
	result, err = db.VerifyIntegrity()
	if err != nil || result.Valid {
		t.Fatalf("checkpoint tampering undetected: %+v %v", result, err)
	}
}

func TestCannotAttachCheckpointToOldHash(t *testing.T) {
	db, _ := tempDB(t)
	seedIntegrityChain(t, db)
	if _, err := db.db.Exec(`UPDATE events SET repository_checkpoint='{}' WHERE id='chain-1'`); err != nil {
		t.Fatal(err)
	}
	result, err := db.VerifyIntegrity()
	if err != nil || result.Valid {
		t.Fatalf("unbound checkpoint accepted: %+v %v", result, err)
	}
}
