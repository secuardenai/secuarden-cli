package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/secuardenai/secuarden-cli/internal/changeledger"
	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
)

func TestObservationCLIEndToEndAndFastIsolatedHook(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "capture")
	db := filepath.Join(dir, "ledger.db")
	repo := filepath.Join(dir, "repo")
	os.Mkdir(repo, 0700)
	git := func(args ...string) string {
		t.Helper()
		b, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v", b, err)
		}
		return strings.TrimSpace(string(b))
	}
	git("init", "-q", "-b", "main")
	git("config", "user.email", "test@example.invalid")
	git("config", "user.name", "Test")
	os.WriteFile(filepath.Join(repo, "f"), []byte("base"), 0600)
	git("add", "f")
	git("commit", "-qm", "base")
	base := git("rev-parse", "HEAD")
	run := func(args ...string) []byte {
		t.Helper()
		b, err := ledgerProcess(args...)
		if err != nil {
			t.Fatalf("%v: %v %s", args, err, b)
		}
		return b
	}
	run("ledger", "capture", "enable", "--capture-dir", capture)
	run("ledger", "checkpoint", "--db", db, "--repo", repo, "--session", "s", "--kind", "start")
	// Hook runs with no usable Git/network executables and an invalid legacy DB.
	home := filepath.Join(dir, "home")
	os.MkdirAll(filepath.Join(home, ".secuarden"), 0700)
	legacy := filepath.Join(home, ".secuarden", "secuarden.db")
	os.WriteFile(legacy, []byte("legacy sentinel"), 0600)
	now := time.Now().UTC()
	payload, _ := json.Marshal(map[string]interface{}{"session_id": "s", "cwd": repo, "hook_event_name": "SessionStart", "timestamp": now.Format(time.RFC3339Nano), "event_id": "start"})
	hook := exec.Command(os.Args[0], "-test.run=^TestLedgerCommandProcess$", "--", "observe-codex", "--capture-dir", capture, "--event", "SessionStart")
	hook.Env = append(os.Environ(), "SECUARDEN_LEDGER_COMMAND_TEST=1", "HOME="+home, "PATH="+filepath.Join(dir, "no-executables"))
	hook.Stdin = bytes.NewReader(payload)
	before := time.Now()
	out, err := hook.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "{}" {
		t.Fatalf("hook acknowledgement: %q %v", out, err)
	}
	if elapsed := time.Since(before); elapsed > 2*time.Second {
		t.Fatalf("hook exceeded timeout: %s", elapsed)
	} else {
		t.Logf("durable hook acknowledgement: %s", elapsed)
	}
	old, _ := os.ReadFile(legacy)
	if string(old) != "legacy sentinel" {
		t.Fatal("hook touched legacy session database")
	}
	entries, _ := os.ReadDir(filepath.Join(capture, "inbox"))
	if len(entries) != 1 {
		t.Fatal("ack preceded durable input")
	}
	// No observation was normalized on the acknowledgement path.
	store, err := changeledger.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := store.Observations("")
	store.Close()
	if err != nil || len(observations) != 0 {
		t.Fatal("hook performed normalization")
	}
	os.WriteFile(filepath.Join(repo, "f"), []byte("head"), 0600)
	git("add", "f")
	git("commit", "-qm", "head")
	run("ledger", "checkpoint", "--db", db, "--repo", repo, "--session", "s", "--kind", "end")
	built := run("ledger", "build", "--db", db, "--repo", repo, "--base", base)
	var result struct {
		Change changeledger.Change `json:"change"`
	}
	if err := json.Unmarshal(built, &result); err != nil {
		t.Fatal(err)
	}
	processed := run("ledger", "process", "--db", db, "--capture-dir", capture)
	if !strings.Contains(string(processed), `"accepted": 1`) {
		t.Fatalf("%s", processed)
	}
	args := []string{"ledger", "correlate", result.Change.Digest, "--db", db, "--capture-dir", capture, "--session", "s", "--since", now.Add(-time.Minute).Format(time.RFC3339Nano), "--until", time.Now().Add(time.Minute).Format(time.RFC3339Nano), "--json"}
	b := run(args...)
	var coverage changeledger.Coverage
	if err := json.Unmarshal(b, &coverage); err != nil {
		t.Fatal(err)
	}
	if coverage.State != "partial" || coverage.Matched != 1 || coverage.Links[0].Confidence != "high" {
		t.Fatalf("%s", b)
	}
	t.Setenv("COLUMNS", "60")
	human := run("ledger", "coverage", result.Change.Digest, "--db", db, "--capture-dir", capture, "--full")
	for _, line := range strings.Split(string(human), "\n") {
		if utf8.RuneCountInString(line) > 60 {
			t.Fatalf("coverage exceeded width: %s", line)
		}
	}
	if !strings.Contains(string(human), "missed_end") || !strings.Contains(string(human), "exact_head_end_checkpoint") {
		t.Fatalf("%s", human)
	}
	run("ledger", "capture", "disable", "--capture-dir", capture)
	_, err = observationcapture.LoadConfig(capture)
	if err != observationcapture.ErrDisabled {
		t.Fatal("disable ineffective")
	}
}
