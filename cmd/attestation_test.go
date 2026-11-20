package cmd

import (
	"bytes"
	"encoding/json"
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
	snapshot := attestation.Snapshot{Components: map[string]string{"hook": "a"}}
	observer := func([]string) attestation.Snapshot { return snapshot }
	s.Apply("enable", []string{"claude-code"}, "", now, observer)
	snapshot = attestation.Snapshot{Components: map[string]string{"hook": "b"}}
	s.Apply("check", nil, "", now.Add(time.Second), observer)
	snapshot = attestation.Snapshot{Components: map[string]string{"hook": "a"}}
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
		for _, want := range []string{"Capture configuration attestation", "deviation", "restored", "matches", "not verified delivery"} {
			if !strings.Contains(b.String(), want) {
				t.Fatalf("missing %s in %s", want, b.String())
			}
		}
	}
}
