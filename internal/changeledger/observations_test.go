package changeledger

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
)

func observationStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func captureInput(t *testing.T, dir, repo, session, event, id string, at time.Time, extra map[string]interface{}) observationcapture.Envelope {
	t.Helper()
	payload := map[string]interface{}{"cwd": repo, "session_id": session, "hook_event_name": event, "event_id": id}
	if !at.IsZero() {
		payload["timestamp"] = at.UTC().Format(time.RFC3339Nano)
	}
	for k, v := range extra {
		payload[k] = v
	}
	b, _ := json.Marshal(payload)
	e, err := observationcapture.Capture(context.Background(), dir, event, "test", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func inboxTest(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "observations")
	if _, err := observationcapture.Configure(dir, true); err != nil {
		t.Fatal(err)
	}
	return dir
}
func assertGap(t *testing.T, c *Coverage, code string) {
	t.Helper()
	for _, g := range c.Reasons {
		if g.Code == code {
			return
		}
	}
	t.Fatalf("missing %s in %+v", code, c.Reasons)
}
func TestObservationExactRevisionAttributionAndLateLifecycle(t *testing.T) {
	s := observationStore(t)
	dir := inboxTest(t)
	repo := repoTest(t)
	writeTest(t, repo, "file", "base")
	base := commitTest(t, repo, "base")
	start, err := s.Checkpoint(repo, "s", "start")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	captureInput(t, dir, repo, "s", "SessionStart", "start", at, nil)
	captureInput(t, dir, repo, "s", "PreToolUse", "pre", at.Add(time.Millisecond), map[string]interface{}{"tool_use_id": "call", "tool_name": "apply_patch"})
	writeTest(t, repo, "file", "head")
	head := commitTest(t, repo, "head")
	// Post is received before its older pre event in a subsequent batch.
	captureInput(t, dir, repo, "s", "PostToolUse", "post", time.Now().UTC(), map[string]interface{}{"tool_use_id": "call", "tool_name": "apply_patch", "tool_response": map[string]interface{}{"success": true}})
	end, err := s.Checkpoint(repo, "s", "end")
	if err != nil {
		t.Fatal(err)
	}
	change := mustBuild(t, BuildOptions{Repository: repo, Base: base, Head: head})
	if _, err = s.Put(change); err != nil {
		t.Fatal(err)
	}
	result, err := s.ProcessInbox(dir, 100)
	if err != nil || result.Accepted != 3 {
		t.Fatalf("%+v %v", result, err)
	}
	coverage, err := s.Correlate(change.Digest, ObservationScope{SessionID: "s", Since: start.ObservedAt, Until: end.ObservedAt})
	if err != nil {
		t.Fatal(err)
	}
	if coverage.State != "partial" || coverage.Matched != 3 {
		t.Fatalf("%+v", coverage)
	}
	for _, l := range coverage.Links {
		if l.Confidence != "high" {
			t.Fatalf("%+v", l)
		}
	}
	assertGap(t, coverage, "missed_end")
	assertGap(t, coverage, "coverage_not_proven")
	// A delayed end inside the recorded revision window resolves missed_end.
	captureInput(t, dir, repo, "s", "SessionEnd", "end", end.ObservedAt, nil)
	if _, err = s.ProcessInbox(dir, 100); err != nil {
		t.Fatal(err)
	}
	coverage, err = s.Coverage(change.Digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range coverage.Reasons {
		if g.Code == "missed_end" {
			t.Fatal("late lifecycle event did not resolve gap")
		}
	}
	// Rewriting the head never reuses old exact checkpoint evidence.
	writeTest(t, repo, "file", "rewritten")
	rewritten := commitTest(t, repo, "force-pushed replacement")
	other := mustBuild(t, BuildOptions{Repository: repo, Base: base, Head: rewritten})
	s.Put(other)
	coverage, err = s.Correlate(other.Digest, ObservationScope{SessionID: "s", Since: start.ObservedAt, Until: end.ObservedAt})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range coverage.Links {
		if l.Confidence != "low" {
			t.Fatalf("stale exact checkpoint reused: %+v", l)
		}
	}
	assertGap(t, coverage, "checkpoint_evidence_missing")
	persisted, _, err := s.Get(change.Digest)
	if err != nil || persisted.Digest != change.Digest {
		t.Fatal("observations changed canonical digest")
	}
}
func TestObservationDuplicateReplayConflictAndRestart(t *testing.T) {
	s := observationStore(t)
	dir := inboxTest(t)
	repo := repoTest(t)
	writeTest(t, repo, "file", "base")
	base := commitTest(t, repo, "base")
	writeTest(t, repo, "file", "head")
	head := commitTest(t, repo, "head")
	c := mustBuild(t, BuildOptions{Repository: repo, Base: base, Head: head})
	s.Put(c)
	at := time.Now().UTC().Add(-time.Minute)
	e := captureInput(t, dir, repo, "s", "PostToolUse", "event", at, map[string]interface{}{"tool_use_id": "call", "tool_response": map[string]interface{}{"exit_code": 0}})
	original, _ := os.ReadFile(filepath.Join(dir, "inbox", e.ID+".json"))
	captureInput(t, dir, repo, "s", "PostToolUse", "event", at, map[string]interface{}{"tool_use_id": "call", "tool_response": map[string]interface{}{"exit_code": 0}})
	r, err := s.ProcessInbox(dir, 100)
	if err != nil || r.Accepted != 1 || r.Duplicates != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	// Model crash after DB commit but before unlink; next process replays safely.
	observationcapture.WriteDurable(filepath.Join(dir, "inbox", e.ID+".json"), original)
	s.beginObservationRun("crashed", dir)
	r, err = s.ProcessInbox(dir, 100)
	if err != nil || r.Replayed != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	captureInput(t, dir, repo, "s", "PostToolUse", "event", at, map[string]interface{}{"tool_use_id": "call", "tool_response": map[string]interface{}{"exit_code": 1}})
	r, err = s.ProcessInbox(dir, 100)
	if err != nil || r.Conflicts != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	coverage, err := s.Correlate(c.Digest, ObservationScope{SessionID: "s", Since: at.Add(-time.Second), Until: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if coverage.Matched != 0 || coverage.Unmatched != 2 || coverage.Duplicates != 1 || coverage.Conflicts != 1 {
		t.Fatalf("%+v", coverage)
	}
	for _, code := range []string{"conflicting_delivery", "duplicate_delivery", "delayed_input", "process_restart", "missed_start", "missed_end", "unmatched_observations"} {
		assertGap(t, coverage, code)
	}
}
func TestObservationRejectionsUnavailableAndCoverageNeverComplete(t *testing.T) {
	s := observationStore(t)
	dir := inboxTest(t)
	repo := repoTest(t)
	writeTest(t, repo, "f", "base")
	base := commitTest(t, repo, "base")
	writeTest(t, repo, "f", "head")
	head := commitTest(t, repo, "head")
	c := mustBuild(t, BuildOptions{Repository: repo, Base: base, Head: head})
	s.Put(c)
	for _, body := range []string{"{", strings.Repeat("x", observationcapture.MaxInputBytes+1)} {
		if _, err := observationcapture.Capture(context.Background(), dir, "Stop", "test", strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	captureInput(t, dir, t.TempDir(), "s", "Stop", "no-repo", time.Time{}, nil)
	r, err := s.ProcessInbox(dir, 100)
	if err != nil || r.Rejected != 2 || r.Accepted != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	coverage, err := s.Correlate(c.Digest, ObservationScope{SessionID: "s", Since: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	observationcapture.ReportTrust(dir, "untrusted")
	coverage.InspectInbox(dir)
	for _, code := range []string{"malformed_input", "oversized_input", "repository_unavailable", "untrusted_hooks", "hook_trust_unverified", "unmatched_observations", "missed_start", "missed_end"} {
		assertGap(t, coverage, code)
	}
	if coverage.State != "unobserved" {
		t.Fatal(coverage.State)
	}
	os.Rename(filepath.Join(dir, "inbox"), filepath.Join(dir, "gone"))
	if _, err = s.ProcessInbox(dir, 100); err == nil {
		t.Fatal("missing inbox silently accepted")
	}
	coverage, err = s.Coverage(c.Digest)
	if err != nil {
		t.Fatal(err)
	}
	assertGap(t, coverage, "inbox_unavailable")
}
func TestObservationOrderingMissingToolPairsAndReceiptConfidence(t *testing.T) {
	s := observationStore(t)
	dir := inboxTest(t)
	repo := repoTest(t)
	writeTest(t, repo, "f", "base")
	base := commitTest(t, repo, "base")
	start, _ := s.Checkpoint(repo, "s", "start")
	now := time.Now().UTC()
	captureInput(t, dir, repo, "s", "PostToolUse", "post", now.Add(-time.Second), map[string]interface{}{"tool_use_id": "call", "sequence": 2, "process_id": "one"})
	s.ProcessInbox(dir, 100)
	captureInput(t, dir, repo, "s", "PreToolUse", "pre", now.Add(-time.Second*2), map[string]interface{}{"tool_use_id": "call", "sequence": 1, "process_id": "two"})
	captureInput(t, dir, repo, "s", "PreToolUse", "unfinished", time.Time{}, map[string]interface{}{"tool_use_id": "unfinished"})
	captureInput(t, dir, repo, "s", "PostToolUse", "orphan", time.Time{}, map[string]interface{}{"tool_use_id": "orphan"})
	writeTest(t, repo, "f", "head")
	head := commitTest(t, repo, "head")
	end, _ := s.Checkpoint(repo, "s", "end")
	s.ProcessInbox(dir, 100)
	c := mustBuild(t, BuildOptions{Repository: repo, Base: base, Head: head})
	s.Put(c)
	coverage, err := s.Correlate(c.Digest, ObservationScope{SessionID: "s", Since: start.ObservedAt.Add(-time.Hour), Until: end.ObservedAt})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"out_of_order", "process_restart", "missing_tool_start", "missing_tool_result", "occurrence_time_unavailable"} {
		assertGap(t, coverage, code)
	}
	for _, l := range coverage.Links {
		if l.Event == "PreToolUse" && l.Confidence == "medium" {
			return
		}
	}
	t.Fatal("receipt-time observation with exact checkpoints was not medium confidence")
}
func TestProcessorDatabaseFailureRetainsDurableInput(t *testing.T) {
	s := observationStore(t)
	dir := inboxTest(t)
	e := captureInput(t, dir, t.TempDir(), "s", "Stop", "one", time.Time{}, nil)
	s.db.Exec(`CREATE TRIGGER fail_delivery BEFORE INSERT ON codex_deliveries BEGIN SELECT RAISE(ABORT,'test failure'); END;`)
	if _, err := s.ProcessInbox(dir, 100); err == nil {
		t.Fatal("database failure ignored")
	}
	if _, err := os.Stat(filepath.Join(dir, "inbox", e.ID+".json")); err != nil {
		t.Fatal("uncommitted input removed")
	}
	obs, err := s.Observations("s")
	if err != nil || len(obs) != 0 {
		t.Fatal("transaction partially committed")
	}
	s.db.Exec(`DROP TRIGGER fail_delivery`)
	r, err := s.ProcessInbox(dir, 100)
	if err != nil || r.Accepted != 1 {
		t.Fatalf("%+v %v", r, err)
	}
}
