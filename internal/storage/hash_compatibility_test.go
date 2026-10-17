package storage

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/events"
	"github.com/secuardenai/secuarden-cli/internal/repository"
)

// Frozen SHA-256 vectors calculated independently from the historical canonical
// JSON projections, not with the production verifier. Changing a hash algorithm
// must not silently change these fixtures.
var historicalHashFixtures = []struct{ name, hash, details string }{
	{"v3", "v3:0fb1e7a7f2199a4110befc650f731525843e32da0d3ff83e85c4ac91aabacfcd", ""},
	{"v4-affected-files", "v4:44c1b11471828426fa51846d196273eced1981e5870213bc242862e85c3b8d7b", ""},
	{"v4-collector-details", "v4:4f008278f96621ee52a84646d1e9a909c4f1e9ae85ca6ae6281d13486fabee2c", `{"hook_type":"PostToolUse","payload":{"output":"redacted fixture"}}`},
}

func seedHistoricalHash(t *testing.T, db *DB, hash, details string) {
	t.Helper()
	if err := db.EnsureSession("compat", "codex", ""); err != nil {
		t.Fatal(err)
	}
	e := &events.Event{ID: "legacy-event", SessionID: "compat", Timestamp: "2026-09-01T00:00:00Z", Source: "secuarden-cli", AgentName: "codex", HookPhase: "post", ActionType: "command_exec", Command: "echo fixture"}
	if err := db.WriteEvent(e); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec("UPDATE events SET event_hash=?, collector_details=? WHERE id=?", hash, details, e.ID); err != nil {
		t.Fatal(err)
	}
}

func requireHashIntegrity(t *testing.T, db *DB, valid bool, count int) {
	t.Helper()
	r, err := db.VerifyIntegrity()
	if err != nil || r.Valid != valid || r.EventsChecked != count {
		t.Fatalf("integrity: %+v, err=%v; want valid=%v count=%d", r, err, valid, count)
	}
}

func TestHistoricalHashMigrationAndMixedChain(t *testing.T) {
	for _, fixture := range historicalHashFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "historical.db")
			db, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if db != nil {
					db.Close()
				}
			}()
			seedHistoricalHash(t, db, fixture.hash, fixture.details)
			// Reproduce columns absent in the historical databases. Open must add them
			// without rewriting an existing event hash or its collector payload.
			columns := []string{"repository_checkpoint"}
			if fixture.details != "" || fixture.name == "v3" {
				columns = append(columns, "affected_files")
			}
			if fixture.details == "" {
				columns = append(columns, "collector_details")
			}
			for _, column := range columns {
				if _, err := db.db.Exec("ALTER TABLE events DROP COLUMN " + column); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = Open(path)
			if err != nil {
				t.Fatal(err)
			}
			requireHashIntegrity(t, db, true, 1)
			var hash, details string
			if err := db.db.QueryRow("SELECT event_hash,COALESCE(collector_details,'') FROM events WHERE id='legacy-event'").Scan(&hash, &details); err != nil {
				t.Fatal(err)
			}
			if hash != fixture.hash || details != fixture.details {
				t.Fatal("migration rewrote historical evidence")
			}
			next := &events.Event{ID: "next", SessionID: "compat", Timestamp: "2026-09-01T00:01:00Z", Source: "secuarden-cli", AgentName: "codex", HookPhase: "post", ActionType: "command_exec", Command: "echo next", RepositoryCheckpoint: &repository.Checkpoint{PreviousSequence: 1, Status: "complete", Kind: "post"}}
			if err := db.WriteEvent(next); err != nil {
				t.Fatal(err)
			}
			var nextPrevious, nextHash string
			if err := db.db.QueryRow("SELECT previous_event_hash,event_hash FROM events WHERE id='next'").Scan(&nextPrevious, &nextHash); err != nil {
				t.Fatal(err)
			}
			if nextPrevious != fixture.hash || !strings.HasPrefix(nextHash, "v5:") {
				t.Fatalf("wrong continuation: previous=%s hash=%s", nextPrevious, nextHash)
			}
			requireHashIntegrity(t, db, true, 2)
			envelope, err := db.ReadSessionEnvelope("compat")
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "collector_details") || strings.Contains(string(encoded), "redacted fixture") {
				t.Fatal("historical local collector payload leaked into upload envelope")
			}
			// A new checkpoint remains protected when it follows either old v4 format.
			if _, err := db.db.Exec("UPDATE events SET repository_checkpoint='{}' WHERE id='next'"); err != nil {
				t.Fatal(err)
			}
			requireHashIntegrity(t, db, false, 2)
		})
	}
}

func TestHistoricalHashesRejectTampering(t *testing.T) {
	mutations := []struct{ name, sql string }{
		{"command", `UPDATE events SET command='changed'`},
		{"previous-hash", `UPDATE events SET previous_event_hash='v4:changed'`},
		{"added-affected-evidence", `UPDATE events SET affected_files='[{"path":"forged.go"}]'`},
		{"added-checkpoint", `UPDATE events SET repository_checkpoint='{}'`},
		{"changed-or-added-collector", `UPDATE events SET collector_details='{"forged":true}'`},
	}
	for _, fixture := range historicalHashFixtures {
		for _, mutation := range mutations {
			t.Run(fixture.name+"/"+mutation.name, func(t *testing.T) {
				db, _ := tempDB(t)
				seedHistoricalHash(t, db, fixture.hash, fixture.details)
				requireHashIntegrity(t, db, true, 1)
				if _, err := db.db.Exec(mutation.sql); err != nil {
					t.Fatal(err)
				}
				requireHashIntegrity(t, db, false, 1)
			})
		}
	}
	for _, value := range []string{"", "null", "{}", "{invalid", " {\"hook_type\":\"PostToolUse\",\"payload\":{\"output\":\"redacted fixture\"}}"} {
		t.Run("collector-removal-or-edit/"+value, func(t *testing.T) {
			fixture := historicalHashFixtures[2]
			db, _ := tempDB(t)
			seedHistoricalHash(t, db, fixture.hash, fixture.details)
			if _, err := db.db.Exec("UPDATE events SET collector_details=?", value); err != nil {
				t.Fatal(err)
			}
			requireHashIntegrity(t, db, false, 1)
		})
	}
}

func TestCheckpointHashRejectsUnboundCollectorDetails(t *testing.T) {
	db, _ := tempDB(t)
	if err := db.EnsureSession("compat", "codex", ""); err != nil {
		t.Fatal(err)
	}
	e := &events.Event{ID: "checkpoint", SessionID: "compat", Timestamp: "2026-09-01T00:00:00Z", Source: "secuarden-cli", AgentName: "codex", HookPhase: "post", ActionType: "command_exec", RepositoryCheckpoint: &repository.Checkpoint{Status: "complete", Kind: "post"}}
	if err := db.WriteEvent(e); err != nil {
		t.Fatal(err)
	}
	requireHashIntegrity(t, db, true, 1)
	if _, err := db.db.Exec(`UPDATE events SET collector_details='{"forged":true}'`); err != nil {
		t.Fatal(err)
	}
	requireHashIntegrity(t, db, false, 1)
}
