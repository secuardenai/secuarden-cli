package privacy

import (
	"strings"
	"testing"
)

func TestRedact_MustRedact(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		pattern string // expected pattern name in matched list
	}{
		{
			"aws_key",
			"export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"env_secret",
		},
		{
			"bearer_token",
			"curl -H 'Authorization: Bearer sk-ant-abc123def456ghi789jkl012mno345pqr'",
			"bearer_token",
		},
		{
			"github_token",
			"GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx npm publish",
			"env_secret",
		},
		{
			"connection_string",
			"postgresql://admin:s3cretP@ss@db.host.com:5432/mydb",
			"connection_string",
		},
		{
			"anthropic_key",
			"key := sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
			"anthropic_key",
		},
		{
			"jwt",
			"token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.dummysignature123",
			"jwt",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scrubbed, matched := Redact(tc.input)
			if scrubbed == tc.input {
				t.Errorf("expected redaction but got original string")
			}
			if !strings.Contains(scrubbed, "[REDACTED:") {
				t.Errorf("expected [REDACTED:...] in output, got: %q", scrubbed)
			}
			found := false
			for _, m := range matched {
				if m == tc.pattern {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected pattern %q in matched %v", tc.pattern, matched)
			}
		})
	}
}

func TestRedact_MustNotRedact(t *testing.T) {
	cases := []string{
		"npm test",
		"git commit -m 'fix auth flow'",
		"reading src/auth/token-validator.ts",
		"exit code: 0",
		"sk-placeholder",     // too short
		"Bearer ",            // no token after
		"hello world",
		"",
	}

	for _, input := range cases {
		scrubbed, matched := Redact(input)
		if scrubbed != input {
			t.Errorf("Redact(%q) modified text unexpectedly to %q (matched: %v)", input, scrubbed, matched)
		}
		if len(matched) > 0 {
			t.Errorf("Redact(%q) unexpectedly matched patterns: %v", input, matched)
		}
	}
}

func TestRedact_Empty(t *testing.T) {
	scrubbed, matched := Redact("")
	if scrubbed != "" || len(matched) != 0 {
		t.Errorf("Redact(\"\") should return empty, got (%q, %v)", scrubbed, matched)
	}
}

func TestRedactFields(t *testing.T) {
	fields := map[string]string{
		"command": "curl -H 'Authorization: Bearer ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
		"output":  "npm test",
	}
	result, names := RedactFields(fields)
	if result["command"] == fields["command"] {
		t.Error("expected command to be redacted")
	}
	if result["output"] != fields["output"] {
		t.Error("expected output to be unchanged")
	}
	found := false
	for _, n := range names {
		if n == "command" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'command' in redacted field names, got %v", names)
	}
}
