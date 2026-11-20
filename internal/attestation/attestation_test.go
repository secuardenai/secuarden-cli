package attestation

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLifecycleRetainsDeviationAndDisable(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "attestation.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	snapshot := Snapshot{Components: map[string]string{"hook": "original"}}
	observer := func([]string) Snapshot { return snapshot }
	apply := func(action string) Report {
		t.Helper()
		now = now.Add(time.Second)
		r, e := s.Apply(action, []string{"claude-code"}, "", now, observer)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	baseline := apply("enable")
	snapshot = Snapshot{Components: map[string]string{"hook": "missing"}}
	r := apply("check")
	if r.Status != "deviated" {
		t.Fatalf("%+v", r)
	}
	snapshot = Snapshot{Components: map[string]string{"hook": "original"}}
	r = apply("check")
	if r.Status != "matches" || len(r.History) != 3 || r.History[1].Kind != "deviation" || r.History[2].Kind != "restored" {
		t.Fatalf("history lost: %+v", r)
	}
	apply("disable")
	snapshot = Snapshot{Components: map[string]string{"hook": "different"}}
	r = apply("check")
	if r.Status != "disabled" {
		t.Fatal(r.Status)
	}
	r = apply("enable")
	if r.Status != "deviated" || r.State.BaselineID != baseline.State.BaselineID {
		t.Fatal("enable silently rebaselined")
	}
	if len(r.History) != 6 {
		t.Fatalf("expected permanent transitions: %+v", r.History)
	}
}
func TestGapUnknownAndExplicitBaseline(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	defer s.Close()
	now := time.Now().UTC()
	observation := Snapshot{Components: map[string]string{"hook": "a"}}
	observe := func([]string) Snapshot { return observation }
	if _, e := s.Apply("enable", []string{"codex"}, "", now, observe); e != nil {
		t.Fatal(e)
	}
	r, e := s.Apply("check", nil, "", now.Add(2*time.Minute), observe)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.History) != 2 || r.History[1].Kind != "observation_gap" || !r.History[1].PreviousObservation.Equal(now) {
		t.Fatalf("missing gap: %+v", r)
	}
	observation = Snapshot{Unknown: true, Problems: []string{"unreadable"}}
	r, e = s.Apply("check", nil, "", now.Add(121*time.Second), observe)
	if e != nil || r.Status != "unknown" {
		t.Fatalf("%+v %v", r, e)
	}
	if _, e = s.Apply("baseline", nil, "", now.Add(122*time.Second), observe); e == nil {
		t.Fatal("baseline without reason")
	}
	observation = Snapshot{Components: map[string]string{"hook": "b"}}
	r, e = s.Apply("baseline", nil, "approved upgrade", now.Add(123*time.Second), observe)
	if e != nil || r.Status != "matches" {
		t.Fatalf("%+v %v", r, e)
	}
	if r.History[len(r.History)-1].Reason != "approved upgrade" {
		t.Fatal("missing baseline reason")
	}
}
func TestCorruptionStopsAppend(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	defer s.Close()
	observe := func([]string) Snapshot { return Snapshot{Components: map[string]string{"x": "a"}} }
	s.Apply("enable", []string{"claude-code"}, "", time.Now(), observe)
	if _, e := s.db.Exec("UPDATE configuration_attestation SET hash='corrupt'"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Apply("check", nil, "", time.Now(), observe); e == nil {
		t.Fatal("accepted corrupted history")
	}
	if _, e := s.Read(time.Now()); e == nil {
		t.Fatal("reported corrupted history as valid")
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

func TestRejectedBaselineRetainsObservedDeviation(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "a.db"))
	defer s.Close()
	now := time.Now()
	snap := Snapshot{Components: map[string]string{"hook": "a"}}
	observe := func([]string) Snapshot { return snap }
	s.Apply("enable", []string{"claude-code"}, "", now, observe)
	snap = Snapshot{Components: map[string]string{}, Problems: []string{"missing hook"}}
	if _, err := s.Apply("baseline", nil, "attempt", now.Add(time.Second), observe); err == nil {
		t.Fatal("accepted incomplete baseline")
	}
	r, err := s.Read(now.Add(time.Second))
	if err != nil || r.Status != "deviated" || len(r.History) != 3 {
		t.Fatalf("lost rejection/deviation: %+v %v", r, err)
	}
}
