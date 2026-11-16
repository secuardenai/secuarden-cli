package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestPolicyUploadAndList(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var output bytes.Buffer
	command := newPolicyCommand()
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"upload", "--file", "../fixtures/policy/flask-security.json"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Imported and activated 1") || !strings.Contains(output.String(), "protect-flask-route-security") {
		t.Fatal(output.String())
	}
	output.Reset()
	command = newPolicyCommand()
	command.SetOut(&output)
	command.SetArgs([]string{"list"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "protect-flask-route-security") {
		t.Fatal(output.String())
	}
}
