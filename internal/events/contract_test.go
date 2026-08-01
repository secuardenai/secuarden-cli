package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadContractFixture(t *testing.T, kind, name string) Event {
	t.Helper()
	p := filepath.Join("..", "..", "fixtures", "stage1", "v2", kind, name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var e Event
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestValidStage1Fixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "fixtures", "stage1", "v2", "valid", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			e := loadContractFixture(t, "valid", filepath.Base(path))
			if err := ValidateProducerInvariants(&e); err != nil {
				t.Fatalf("valid fixture rejected: %v", err)
			}
		})
	}
}

func TestInvalidStage1Fixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "fixtures", "stage1", "v2", "invalid", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			e := loadContractFixture(t, "invalid", filepath.Base(path))
			if err := ValidateProducerInvariants(&e); err == nil {
				t.Fatal("invalid fixture accepted")
			}
		})
	}
}

func TestMissingInvocationReasonIsToolLifecycleOnly(t *testing.T) {
	e := loadContractFixture(t, "valid", "partial-pre-missing-invocation.json")
	e.HookPhase = HookPhaseSessionStart
	e.ActionType = ActionSessionStart
	e.ToolName = ""
	if err := ValidateProducerInvariants(&e); err == nil {
		t.Fatal("lifecycle event accepted with missing_invocation_id reason")
	}
}

func TestApprovedContentIsNotAProducerCapability(t *testing.T) {
	e := loadContractFixture(t, "valid", "file-write-post.json")
	e.PrivacyMode = "approved_content"
	if err := ValidateProducerInvariants(&e); err == nil {
		t.Fatal("CLI producer accepted unsupported approved_content mode")
	}
}
