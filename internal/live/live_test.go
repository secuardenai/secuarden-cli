package live

import (
	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"os/exec"
	"testing"
	"time"
)

// Synthetic metadata fixtures test evaluation, not live client acceptance.
func TestEvidence(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", dir).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	root, err := repository.ResolveCurrent(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := State{Started: time.Now().Add(-time.Second), Agent: "codex", Session: "selected", Repository: root.Root}
	start := storage.LiveRecord{CapturedAt: time.Now().UTC().Format(time.RFC3339Nano), ID: "start", Session: s.Session, Agent: s.Agent, Directory: dir, Phase: "session_start"}
	pre := start
	pre.ID = "pre"
	pre.Phase = "pre"
	pre.Tool = "exec_command"
	pre.Invocation = "call"
	post := pre
	post.ID = "post"
	post.Phase = "post"
	unrelated := post
	unrelated.Session = "desktop-other"
	wrongRepo := post
	wrongRepo.Directory = t.TempDir()
	oldRecord := post
	oldRecord.CapturedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	wrongCall := post
	wrongCall.Invocation = "other"
	tests := []struct {
		name     string
		records  []storage.LiveRecord
		old      bool
		failures int
		want     string
	}{
		{"old timestamp", []storage.LiveRecord{oldRecord}, false, 0, "no_matching_event"},
		{"configured idle", nil, false, 0, "no_matching_event"},
		{"old session", []storage.LiveRecord{start, pre, post}, true, 0, "session_not_fresh"},
		{"another client session", []storage.LiveRecord{unrelated}, false, 0, "no_matching_event"},
		{"metadata only pair", []storage.LiveRecord{start, pre, post}, false, 0, "tool_round_trip"},
		{"missing post", []storage.LiveRecord{start, pre}, false, 0, "request_received_result_missing"},
		{"duplicates", []storage.LiveRecord{start, pre, pre}, false, 0, "request_received_result_missing"},
		{"duplicate valid pair", []storage.LiveRecord{start, pre, post, post}, false, 0, "tool_round_trip"},
		{"unrelated invocation", []storage.LiveRecord{start, pre, wrongCall}, false, 0, "request_received_result_missing"},
		{"unrelated repo", []storage.LiveRecord{start, pre, wrongRepo}, false, 0, "request_received_result_missing"},
		{"failure", []storage.LiveRecord{start, pre, post}, false, 1, "capture_persistence_failure"},
		{"no fresh start", []storage.LiveRecord{pre, post}, false, 0, "fresh_session_start_missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stage, ids, _ := Evaluate(s, tt.records, tt.old, tt.failures)
			if stage != tt.want {
				t.Fatalf("got %s want %s", stage, tt.want)
			}
			if stage == "tool_round_trip" && len(ids) != 3 {
				t.Fatal(ids)
			}
		})
	}
	s.Agent = "claude-code"
	start.Agent = s.Agent
	pre.Agent = s.Agent
	post.Agent = s.Agent
	if stage, _, _ := Evaluate(s, []storage.LiveRecord{start, pre, post}, false, 0); stage != "tool_round_trip" {
		t.Fatal(stage)
	}
}
