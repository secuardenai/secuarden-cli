package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

type stubAdapter struct{}

var _ Adapter = stubAdapter{}

func (stubAdapter) Descriptor() Descriptor {
	return Descriptor{
		APIVersion: APIVersion, ID: "stub", Version: "1.0.0", AgentFamily: "stub-agent",
	}
}

func (stubAdapter) Capabilities() Capabilities {
	return Capabilities{Hooks: []HookCapability{{
		Hook:        "before_action",
		Actions:     []string{"file_write"},
		Enforcement: EnforcementSynchronous,
		Decisions:   []DecisionKind{DecisionAllow, DecisionDeny, DecisionRequireApproval},
	}}}
}

func (stubAdapter) Validate(input RawEvent) error {
	if input.Hook != "before_action" {
		return fmt.Errorf("%w: %s", ErrUnsupportedHook, input.Hook)
	}
	var payload struct {
		SessionID    string `json:"session_id"`
		InvocationID string `json:"invocation_id"`
		Path         string `json:"path"`
	}
	if err := json.Unmarshal(input.Payload, &payload); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if payload.SessionID == "" || payload.InvocationID == "" || payload.Path == "" {
		return fmt.Errorf("%w: missing required stub field", ErrInvalidInput)
	}
	return nil
}

func (s stubAdapter) Normalize(input RawEvent) (ActionProposal, error) {
	if err := s.Validate(input); err != nil {
		return ActionProposal{}, err
	}
	var payload struct {
		SessionID    string `json:"session_id"`
		InvocationID string `json:"invocation_id"`
		Path         string `json:"path"`
	}
	_ = json.Unmarshal(input.Payload, &payload)
	return ActionProposal{
		SessionID: payload.SessionID, InvocationID: payload.InvocationID,
		Hook: input.Hook, ActionType: "file_write", ToolName: "stub_write",
		Attributes: map[string]interface{}{"file_path": payload.Path},
	}, nil
}

func (s stubAdapter) RenderDecision(_ ActionProposal, decision PolicyDecision) (AgentResponse, error) {
	if err := decision.Validate(); err != nil {
		return AgentResponse{}, err
	}
	capability, _ := s.Capabilities().ForHook("before_action")
	if !capability.SupportsDecision(decision.Kind) {
		return AgentResponse{}, fmt.Errorf("%w: %s", ErrUnsupportedDecision, decision.Kind)
	}
	payload, _ := json.Marshal(map[string]string{"decision": string(decision.Kind), "reason": decision.Reason})
	return AgentResponse{Payload: payload, ExitCode: 0}, nil
}

func TestAdapterContractWithStubbedData(t *testing.T) {
	var subject Adapter = stubAdapter{}
	if err := subject.Descriptor().Validate(); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if err := subject.Capabilities().Validate(); err != nil {
		t.Fatalf("capabilities: %v", err)
	}

	input := RawEvent{
		Hook:    "before_action",
		Payload: json.RawMessage(`{"session_id":"session-1","invocation_id":"call-1","path":"src/auth.go"}`),
	}
	proposal, err := subject.Normalize(input)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if proposal.ActionType != "file_write" || proposal.Attributes["file_path"] != "src/auth.go" {
		t.Fatalf("unexpected proposal: %+v", proposal)
	}

	for _, kind := range []DecisionKind{DecisionAllow, DecisionDeny, DecisionRequireApproval} {
		response, err := subject.RenderDecision(proposal, PolicyDecision{ID: "decision-1", Kind: kind, Reason: "stubbed"})
		if err != nil {
			t.Fatalf("render %s: %v", kind, err)
		}
		var rendered map[string]string
		if err := json.Unmarshal(response.Payload, &rendered); err != nil {
			t.Fatalf("parse response for %s: %v", kind, err)
		}
		if rendered["decision"] != string(kind) {
			t.Fatalf("rendered decision = %q, want %q", rendered["decision"], kind)
		}
	}
}

func TestStubAdapterRejectsInvalidInputAndDecision(t *testing.T) {
	subject := stubAdapter{}
	if _, err := subject.Normalize(RawEvent{Hook: "after_action", Payload: json.RawMessage(`{}`)}); !errors.Is(err, ErrUnsupportedHook) {
		t.Fatalf("normalize error = %v, want ErrUnsupportedHook", err)
	}
	if _, err := subject.Normalize(RawEvent{Hook: "before_action", Payload: json.RawMessage(`{}`)}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("normalize error = %v, want ErrInvalidInput", err)
	}
	if _, err := subject.RenderDecision(ActionProposal{}, PolicyDecision{ID: "decision-1", Kind: "invented"}); !errors.Is(err, ErrUnsupportedDecision) {
		t.Fatalf("render error = %v, want ErrUnsupportedDecision", err)
	}
}
