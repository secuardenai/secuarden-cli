package cmd

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/events"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func executeVerify(args ...string) (string, error) {
	c := newVerifyCommand()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&out)
	c.SetArgs(args)
	err := c.Execute()
	return out.String(), err
}

func TestVerifyRepositoryScopes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	parent := t.TempDir()
	first := filepath.Join(parent, "first")
	second := filepath.Join(parent, "second")
	for _, dir := range []string{first, second} {
		if out, err := exec.Command("git", "init", "--quiet", dir).CombinedOutput(); err != nil {
			t.Fatalf("git init: %v %s", err, out)
		}
	}
	path, _ := storage.DefaultDBPath()
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, dir := range []string{first, second} {
		id := fmt.Sprintf("session-%d", i)
		if err := db.EnsureSession(id, "codex", dir); err != nil {
			t.Fatal(err)
		}
		for n := 1; n <= 2; n++ {
			if err := db.WriteEvent(&events.Event{ID: fmt.Sprintf("%s-%d", id, n), SessionID: id, Sequence: n, AgentName: "codex", WorkingDirectory: filepath.Join(dir, "subdirectory")}); err != nil {
				t.Fatal(err)
			}
		}
	}
	db.Close()
	previous, _ := os.Getwd()
	if err := os.Chdir(first); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	for _, test := range []struct {
		args             []string
		events, sessions int
		scope            string
	}{
		{[]string{"--json"}, 2, 1, "repository"},
		{[]string{"--repo", second, "--json"}, 2, 1, "repository"},
		{[]string{"--all", "--json"}, 4, 2, "all"},
	} {
		out, err := executeVerify(test.args...)
		if err != nil {
			t.Fatalf("%v: %v %s", test.args, err, out)
		}
		var report verificationReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatal(err)
		}
		if report.EventsChecked != test.events || report.SessionsChecked != test.sessions || report.Scope != test.scope || !report.Valid {
			t.Fatalf("report=%+v", report)
		}
	}
	if err := os.Chdir(parent); err != nil {
		t.Fatal(err)
	}
	if _, err := executeVerify(); err == nil || !strings.Contains(err.Error(), "--repo <path> or --all") {
		t.Fatalf("outside repo: %v", err)
	}
	for _, args := range [][]string{{"--repo", first, "--all"}, {"--details", "--json"}, {"--repo", filepath.Join(parent, "missing")}} {
		if _, err := executeVerify(args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestVerifyEmptyScopeIsNotSuccess(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	out, err := executeVerify("--all", "--json")
	if err == nil {
		t.Fatal("empty verification succeeded")
	}
	var report verificationReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Valid || report.Status != "no_records" {
		t.Fatalf("report=%+v", report)
	}
	out, _ = executeVerify("--all")
	if !strings.Contains(out, "NO RECORDS") || strings.Contains(out, "VERIFIED") || strings.Contains(out, "Usage:") {
		t.Fatal(out)
	}
}

func TestVerificationTableIsBoundedAndDetailsComplete(t *testing.T) {
	result := &storage.IntegrityResult{EventsChecked: 30, SessionsChecked: 12}
	repos := map[string]string{}
	for i := 0; i < 12; i++ {
		id := fmt.Sprintf("session-%02d", i)
		repos[id] = "example.com/team/repo"
		result.Findings = append(result.Findings, storage.IntegrityFinding{SessionID: id, Sequence: 1, Agent: "codex", Kind: "event_hash_mismatch"}, storage.IntegrityFinding{SessionID: id, Sequence: 1, Agent: "codex", Kind: "broken_chain"})
	}
	report := verificationReport{IntegrityResult: result, Status: "failed", Scope: "all", Storage: "test.db"}
	var out bytes.Buffer
	if err := renderVerification(&out, report, repos, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"FAILED", "12 events across 12 sessions", "Showing 10 of 12", "Event hash mismatch", "Broken event chain"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "session-11") {
		t.Fatal("unbounded summary")
	}
	out.Reset()
	if err := renderVerification(&out, report, repos, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "session-11:1") || strings.Contains(out.String(), "Showing 10") {
		t.Fatal(out.String())
	}
}

func TestVerifyFailedJSONAndTerminalExit(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path, _ := storage.DefaultDBPath()
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureSession("damaged-session", "codex", "/missing/repo"); err != nil {
		t.Fatal(err)
	}
	if err := db.WriteEvent(&events.Event{ID: "damaged-event", SessionID: "damaged-session", Sequence: 1, AgentName: "codex"}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE events SET command='altered'`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	out, err := executeVerify("--all", "--json")
	if err == nil {
		t.Fatal("invalid JSON verification succeeded")
	}
	var report verificationReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Valid || report.Status != "failed" || len(report.Findings) != 1 || len(report.Failures) != 1 {
		t.Fatalf("report=%+v", report)
	}
	out, err = executeVerify("--all")
	if err == nil || !strings.Contains(out, "Event hash mismatch") || strings.Contains(out, "Usage:") || strings.Contains(out, "Error:") {
		t.Fatalf("output=%s err=%v", out, err)
	}
}

func TestVerificationTableKeepsAmbiguousIdentifiers(t *testing.T) {
	ids := []string{"same-prefix-session-a", "same-prefix-session-b"}
	repos := map[string]string{ids[0]: "example.com/one/repo", ids[1]: "example.com/two/repo"}
	result := &storage.IntegrityResult{}
	for _, id := range ids {
		result.Findings = append(result.Findings, storage.IntegrityFinding{SessionID: id, Agent: "codex", Kind: "session_hash_mismatch"})
	}
	var out bytes.Buffer
	if err := renderVerification(&out, verificationReport{IntegrityResult: result, Status: "failed", Scope: "all"}, repos, false); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if !strings.Contains(out.String(), id) || !strings.Contains(out.String(), repos[id]) {
			t.Fatal(out.String())
		}
	}
	if !strings.Contains(out.String(), "0 events across 2 sessions") {
		t.Fatal(out.String())
	}
}
