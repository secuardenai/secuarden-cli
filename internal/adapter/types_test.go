package adapter

import (
	"errors"
	"testing"
)

func TestDescriptorValidation(t *testing.T) {
	valid := Descriptor{APIVersion: APIVersion, ID: "codex", Version: "1.2.3", AgentFamily: "codex"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}

	tests := []struct {
		name string
		in   Descriptor
		want error
	}{
		{"API version", Descriptor{APIVersion: "2.0.0", ID: "codex", Version: "1.2.3", AgentFamily: "codex"}, ErrIncompatibleVersion},
		{"ID", Descriptor{APIVersion: APIVersion, Version: "1.2.3", AgentFamily: "codex"}, ErrInvalidDescriptor},
		{"version", Descriptor{APIVersion: APIVersion, ID: "codex", AgentFamily: "codex"}, ErrInvalidDescriptor},
		{"agent family", Descriptor{APIVersion: APIVersion, ID: "codex", Version: "1.2.3"}, ErrInvalidDescriptor},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.in.Validate(); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCapabilityValidationAndQueries(t *testing.T) {
	capabilities := Capabilities{Hooks: []HookCapability{{
		Hook:        "before_action",
		Actions:     []string{"file_write", "command_exec"},
		Enforcement: EnforcementSynchronous,
		Decisions:   []DecisionKind{DecisionAllow, DecisionDeny},
	}}}
	if err := capabilities.Validate(); err != nil {
		t.Fatalf("valid capabilities rejected: %v", err)
	}
	hook, ok := capabilities.ForHook("before_action")
	if !ok || !hook.SupportsAction("file_write") || !hook.SupportsDecision(DecisionDeny) {
		t.Fatalf("capability query failed: %+v, found=%v", hook, ok)
	}
	if hook.SupportsAction("network_request") || hook.SupportsDecision(DecisionRequireApproval) {
		t.Fatal("capability query reported undeclared support")
	}
}

func TestCapabilityValidationRejectsAmbiguity(t *testing.T) {
	tests := []Capabilities{
		{Hooks: []HookCapability{{Hook: "", Enforcement: EnforcementObserveOnly}}},
		{Hooks: []HookCapability{{Hook: "event", Enforcement: "sometimes"}}},
		{Hooks: []HookCapability{{Hook: "event", Enforcement: EnforcementObserveOnly, Actions: []string{"read", "read"}}}},
		{Hooks: []HookCapability{{Hook: "event", Enforcement: EnforcementSynchronous, Decisions: []DecisionKind{"invented"}}}},
		{Hooks: []HookCapability{{Hook: "event", Enforcement: EnforcementObserveOnly}, {Hook: "event", Enforcement: EnforcementObserveOnly}}},
	}
	for i, capabilities := range tests {
		if err := capabilities.Validate(); !errors.Is(err, ErrInvalidCapabilities) {
			t.Fatalf("case %d error = %v, want ErrInvalidCapabilities", i, err)
		}
	}
}

func TestPolicyDecisionValidation(t *testing.T) {
	if err := (PolicyDecision{ID: "decision-1", Kind: DecisionAllow}).Validate(); err != nil {
		t.Fatalf("valid decision rejected: %v", err)
	}
	for _, decision := range []PolicyDecision{{Kind: DecisionAllow}, {ID: "decision-1", Kind: "invented"}} {
		if err := decision.Validate(); !errors.Is(err, ErrUnsupportedDecision) {
			t.Fatalf("error = %v, want ErrUnsupportedDecision", err)
		}
	}
}
