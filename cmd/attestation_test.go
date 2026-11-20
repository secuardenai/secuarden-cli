package cmd

import (
	"bytes"
	"encoding/json"
	"github.com/spf13/cobra"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/attestation"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func TestAttestationCommandDisablePersistsAndCheckFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	run := func(args ...string) (string, error) {
		c := newAttestationCommand()
		var b bytes.Buffer
		c.SetOut(&b)
		c.SetErr(&b)
		c.SetArgs(args)
		e := c.Execute()
		return b.String(), e
	}
	out, e := run("disable", "--json")
	if e != nil {
		t.Fatal(e)
	}
	var r attestation.Report
	if json.Unmarshal([]byte(out), &r) != nil || r.Status != "disabled" {
		t.Fatal(out)
	}
	if e := initializeAttestation(true, false); e != nil {
		t.Fatal(e)
	}
	out, e = run("check", "--json")
	if e == nil || !strings.Contains(out, `"status": "disabled"`) {
		t.Fatalf("disabled check: %s %v", out, e)
	}
	out, e = run("verify", "--json")
	if e != nil || !strings.Contains(out, `"kind": "disabled"`) {
		t.Fatalf("history was lost: %s %v", out, e)
	}
}
func TestReportRetainsConfigurationHistoryWithNoActivity(t *testing.T) {
	s, e := attestation.Open(filepath.Join(t.TempDir(), "a.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now()
	snapshot := commandObservation("pass")
	observer := func([]string) attestation.Snapshot { return snapshot }
	s.Apply("enable", []string{"claude-code"}, "", now, observer)
	snapshot = commandObservation("fail")
	s.Apply("check", nil, "", now.Add(time.Second), observer)
	snapshot = commandObservation("pass")
	r, e := s.Apply("check", nil, "", now.Add(2*time.Second), observer)
	if e != nil {
		t.Fatal(e)
	}
	for _, markdown := range []bool{false, true} {
		var b bytes.Buffer
		report := &storage.AccountabilityReport{Since: now.Format(time.RFC3339), Until: now.Format(time.RFC3339), ConfigurationAttestation: &r}
		if e := renderReportWithLimit(&b, report, markdown, 10); e != nil {
			t.Fatal(e)
		}
		for _, want := range []string{"Capture configuration attestation", "deviation", "restored", "capture contract satisfied", "not verified delivery"} {
			if !strings.Contains(b.String(), want) {
				t.Fatalf("missing %s in %s", want, b.String())
			}
		}
	}
}

func commandObservation(status string) attestation.Snapshot {
	return attestation.Snapshot{Contracts: []attestation.ContractRef{{Adapter: "claude-code", Version: "1", Digest: "contract"}}, Results: []attestation.RequirementResult{{ID: "pre-hook", Status: status}}}
}
func TestBaselineCommandCannotRedefineCompliance(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	c := newAttestationCommand()
	c.SetArgs([]string{"baseline", "--reason", "accept"})
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	if e := c.Execute(); e == nil || !strings.Contains(e.Error(), "no longer supported") {
		t.Fatal(e)
	}
}

func TestEnableRecordsInitialContractViolation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	c := newAttestationCommand()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&bytes.Buffer{})
	c.SetArgs([]string{"enable", "--agent", "claude-code", "--json"})
	if err := c.Execute(); err == nil {
		t.Fatal("enable reported success with missing configuration")
	}
	var r attestation.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Status != "violated" || !r.State.Enabled || len(r.State.Contracts) != 1 {
		t.Fatalf("violation not recorded for subsequent monitoring: %+v", r)
	}
	if r.State.Contracts[0].Version != "1" {
		t.Fatal("no contract version")
	}
}

func TestUnconfiguredAttestationHasGuidanceAndSingleErrorOwner(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := &cobra.Command{Use: "secuarden"}
	root.AddCommand(newAttestationCommand())
	var out, stderr bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&stderr)
	root.SetArgs([]string{"attestation", "check", "--json"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "secuarden attestation enable") {
		t.Fatalf("missing setup guidance: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("Cobra printed error that main will also print: %s", stderr.String())
	}
	var report attestation.Report
	if e := json.Unmarshal(out.Bytes(), &report); e != nil || report.Status != "not_configured" {
		t.Fatalf("structured status changed: %s %v", out.String(), e)
	}
}
