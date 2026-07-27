package risk

import "testing"

func TestAssess(t *testing.T) {
	if got := Assess("internal/auth/session.go", false); got.Level != "high" {
		t.Fatalf("auth change should be high risk: %+v", got)
	}
	if got := Assess("docs/quickstart.md", false); got.Level != "low" {
		t.Fatalf("documentation should be low risk: %+v", got)
	}
	if got := Assess(".env.production", true); got.Level != "critical" {
		t.Fatalf("sensitive environment file should be critical: %+v", got)
	}
}
