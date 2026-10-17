package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/changeledger"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

// Execute the registered CLI in a fresh process so Cobra's global flag state
// cannot leak between build/show calls or other command tests.
func TestLedgerCommandProcess(t *testing.T) {
	if os.Getenv("SECUARDEN_LEDGER_COMMAND_TEST") != "1" {
		return
	}
	rootCmd.SetArgs(os.Args[3:]) // test binary, -test.run=..., --, CLI args
	if err := Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func ledgerProcess(args ...string) ([]byte, error) {
	command := exec.Command(os.Args[0], append([]string{"-test.run=^TestLedgerCommandProcess$", "--"}, args...)...)
	command.Env = append(os.Environ(), "SECUARDEN_LEDGER_COMMAND_TEST=1")
	var out, stderr bytes.Buffer
	command.Stdout, command.Stderr = &out, &stderr
	if err := command.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return out.Bytes(), nil
}

func TestLedgerCommandsWithoutCapture(t *testing.T) {
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	git("config", "user.name", "Ledger Test")
	git("config", "user.email", "ledger@example.invalid")
	if err := os.WriteFile(filepath.Join(repo, "file.txt"), []byte("committed revision"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", "file.txt")
	git("commit", "-qm", "base")
	base := git("rev-parse", "HEAD")
	git("mv", "file.txt", "renamed.txt")
	git("commit", "-qm", "rename")
	head := git("rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(repo, "dirty.txt"), []byte("context only"), 0600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	sessionPath := filepath.Join(dir, "secuarden.db")
	session, err := storage.Open(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.SetMeta("ledger-test", "preserve session data"); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	sessionBefore, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(dir, "ledger.db")
	output, err := ledgerProcess("ledger", "build", "--repo", repo, "--base", base, "--head", head, "--db", ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		Change  changeledger.Change  `json:"change"`
		Receipt changeledger.Receipt `json:"receipt"`
	}
	var built, shown result
	if err := json.Unmarshal(output, &built); err != nil {
		t.Fatalf("invalid build output: %v: %s", err, output)
	}
	if built.Change.Status != "complete" || built.Change.HeadCommit != head || built.Change.BaseCommit != base || built.Receipt.Database != ledgerPath || built.Receipt.ChangeDigest != built.Change.Digest {
		t.Fatalf("wrong CLI revision: %+v", built)
	}
	if built.Change.WorktreeDirty == nil || !*built.Change.WorktreeDirty || len(built.Change.ChangedPaths) != 1 || built.Change.ChangedPaths[0].Path != "renamed.txt" {
		t.Fatalf("dirty context leaked into revision: %+v", built.Change)
	}
	output, err = ledgerProcess("ledger", "show", built.Change.Digest, "--db", ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output, &shown); err != nil || !reflect.DeepEqual(built, shown) {
		t.Fatalf("show did not preserve build record and receipt: %v: %s", err, output)
	}
	sessionAfter, err := os.ReadFile(sessionPath)
	if err != nil || !bytes.Equal(sessionBefore, sessionAfter) {
		t.Fatalf("ledger commands modified session database: %v", err)
	}
	defaultLedger, err := changeledger.DefaultDBPath()
	if err != nil {
		t.Fatal(err)
	}
	defaultSession, err := storage.DefaultDBPath()
	if err != nil || defaultLedger == defaultSession || filepath.Dir(defaultLedger) != filepath.Dir(defaultSession) || filepath.Base(defaultLedger) != "ledger.db" {
		t.Fatalf("incorrect default ledger path: ledger=%q session=%q err=%v", defaultLedger, defaultSession, err)
	}

	failedPath := filepath.Join(dir, "failed.db")
	output, err = ledgerProcess("ledger", "build", "--repo", repo, "--base", base, "--head", "missing-ref", "--db", failedPath)
	if err == nil {
		t.Fatal("unavailable revision should fail")
	}
	var partial changeledger.Change
	if err := json.Unmarshal(output, &partial); err != nil || partial.Status != "partial" || partial.Digest != "" || len(partial.CaptureGaps) == 0 {
		t.Fatalf("missing partial record and capture gap: %v: %s", err, output)
	}
	if _, err := os.Stat(failedPath); !os.IsNotExist(err) {
		t.Fatalf("partial revision created database: %v", err)
	}
}
