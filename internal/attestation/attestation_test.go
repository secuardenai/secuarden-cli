package attestation

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testObservation(status, version string) Snapshot {
	return Snapshot{Contracts: []ContractRef{{Adapter: "claude-code", Version: version, Digest: "contract-" + version}}, Results: []RequirementResult{{ID: "claude-code/pre", Status: status, Reason: status}}}
}
func TestLifecycleRetainsDeviationAndDisable(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	snapshot := testObservation("pass", "1")
	observe := func([]string) Snapshot { return snapshot }
	apply := func(action string) Report {
		t.Helper()
		now = now.Add(time.Second)
		r, e := s.Apply(action, []string{"claude-code"}, "", now, observe)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	if r := apply("enable"); r.Status != "satisfied" {
		t.Fatal(r)
	}
	snapshot = testObservation("fail", "1")
	if r := apply("check"); r.Status != "violated" {
		t.Fatal(r)
	}
	snapshot = testObservation("pass", "1")
	r := apply("check")
	if r.Status != "satisfied" || r.History[len(r.History)-1].Kind != "restored" {
		t.Fatal(r)
	}
	apply("disable")
	snapshot = testObservation("fail", "1")
	if r := apply("check"); r.Status != "disabled" {
		t.Fatal(r)
	}
	r = apply("enable")
	if r.Status != "violated" {
		t.Fatal("reenable accepted violation")
	}
	found := false
	for _, e := range r.History {
		if e.Kind == "deviation" {
			found = true
		}
	}
	if !found {
		t.Fatal("lost history")
	}
}
func TestInitialViolationCannotBeAccepted(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	defer s.Close()
	now := time.Now()
	observe := func([]string) Snapshot { return testObservation("fail", "1") }
	r, e := s.Apply("enable", []string{"claude-code"}, "", now, observe)
	if e != nil || r.Status != "violated" {
		t.Fatalf("%+v %v", r, e)
	}
	if _, e = s.Apply("baseline", nil, "accept broken hooks", now, observe); e == nil {
		t.Fatal("accepted machine-defined compliance")
	}
}
func TestGapUnknownAndContractUpgrade(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	defer s.Close()
	now := time.Now().UTC()
	snapshot := testObservation("pass", "1")
	observe := func([]string) Snapshot { return snapshot }
	s.Apply("enable", []string{"claude-code"}, "", now, observe)
	r, e := s.Apply("check", nil, "", now.Add(2*time.Minute), observe)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, e := range r.History {
		if e.Kind == "observation_gap" && e.PreviousObservation.Equal(now) {
			found = true
		}
	}
	if !found {
		t.Fatal("missing gap")
	}
	snapshot = testObservation("unknown", "1")
	r, e = s.Apply("check", nil, "", now.Add(121*time.Second), observe)
	if e != nil || r.Status != "unknown" {
		t.Fatalf("%+v %v", r, e)
	}
	snapshot = testObservation("pass", "2")
	r, e = s.Apply("check", nil, "", now.Add(122*time.Second), observe)
	if e != nil || r.Status != "satisfied" {
		t.Fatalf("%+v %v", r, e)
	}
	if r.History[len(r.History)-2].Kind != "contract_changed" || r.State.Contracts[0].Version != "2" {
		t.Fatal("missing contract transition")
	}
}
func TestCorruptionStopsAppend(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	defer s.Close()
	observe := func([]string) Snapshot { return testObservation("pass", "1") }
	s.Apply("enable", []string{"claude-code"}, "", time.Now(), observe)
	if _, e := s.db.Exec("UPDATE configuration_attestation SET hash='corrupt'"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Apply("check", nil, "", time.Now(), observe); e == nil {
		t.Fatal("accepted corrupted history")
	}
	if _, e := s.Read(time.Now()); e == nil {
		t.Fatal("reported corrupt history as valid")
	}
}
func TestLegacyHistoryMigratesWithoutRewrite(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	defer s.Close()
	const body = `{"sequence":1,"kind":"baseline","observed_at":"2026-11-20T00:00:00Z","previous_observation":"0001-01-01T00:00:00Z","state":{"enabled":true,"agents":["claude-code"],"baseline":{"components":{"hook":"old"}},"baseline_id":"legacy","configuration":"matches","last_observed":"2026-11-20T00:00:00Z","last_matching":"2026-11-20T00:00:00Z"},"previous_hash":"","hash":""}`
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
	if _, e := s.db.Exec("INSERT INTO configuration_attestation VALUES (1,?,?)", body, hash); e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 11, 20, 0, 0, 1, 0, time.UTC)
	r, e := s.Read(now)
	if e != nil || r.Status != "legacy_unverified" {
		t.Fatalf("%+v %v", r, e)
	}
	r, e = s.Apply("check", nil, "", now, func([]string) Snapshot { return testObservation("fail", "1") })
	if e != nil || r.Status != "violated" {
		t.Fatalf("%+v %v", r, e)
	}
	if r.History[0].Hash != hash || r.History[1].Kind != "contract_migrated" {
		t.Fatal("legacy history changed")
	}
	var stored string
	s.db.QueryRow("SELECT body FROM configuration_attestation WHERE sequence=1").Scan(&stored)
	if stored != body {
		t.Fatal("rewrote original record")
	}
}
func TestDisabledNeverObservesAndConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.db")
	s, _ := Open(path)
	defer s.Close()
	observe := func([]string) Snapshot { t.Fatal("disabled observer called"); return Snapshot{} }
	if _, e := s.Apply("disable", nil, "", time.Now(), observe); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other, e := Open(path)
			if e != nil {
				t.Error(e)
				return
			}
			defer other.Close()
			if _, e = other.Apply("check", nil, "", time.Now(), observe); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	r, e := s.Read(time.Now())
	if e != nil || r.Status != "disabled" || len(r.History) != 1 {
		t.Fatalf("%+v %v", r, e)
	}
}
func TestCurrentDoesNotCreateStore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := Current(nil, true)
	if r.Status != "not_configured" {
		t.Fatal(r)
	}
}
