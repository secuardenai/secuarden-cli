package codex

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/adapter"
)

func TestCodexAdapterContract(t *testing.T) {
	subject := Adapter{}
	if err := subject.Descriptor().Validate(); err != nil {
		t.Fatal(err)
	}
	if err := subject.Capabilities().Validate(); err != nil {
		t.Fatal(err)
	}
	input := adapter.RawEvent{Hook: "PermissionRequest", Payload: json.RawMessage(`{"session_id":"s1","tool_name":"Bash","tool_use_id":"c1","permission_mode":"default","reason":"needs escalation","tool_input":{"command":"echo ok"}}`)}
	proposal, err := subject.Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.ActionType != "command_exec" || proposal.Attributes["permission_mode"] != "default" || proposal.Attributes["reason"] != "needs escalation" || proposal.Attributes["tool_input"] == nil {
		t.Fatalf("unexpected normalized proposal: %#v", proposal)
	}
	response, err := subject.RenderDecision(proposal, adapter.PolicyDecision{ID: "d1", Kind: adapter.DecisionDeny, Reason: "repository policy"})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(response.Payload, &body); err != nil {
		t.Fatal(err)
	}
	hook, ok := body["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected hookSpecificOutput type: %T", body["hookSpecificOutput"])
	}
	decision, ok := hook["decision"].(map[string]interface{})
	if !ok {
		t.Fatalf("unexpected decision type: %T", hook["decision"])
	}
	if decision["behavior"] != "deny" || decision["message"] != "repository policy" {
		t.Fatalf("unexpected response: %#v", body)
	}
	if _, err := subject.RenderDecision(proposal, adapter.PolicyDecision{ID: "d2", Kind: adapter.DecisionRequireApproval}); !errors.Is(err, adapter.ErrUnsupportedDecision) {
		t.Fatalf("require_approval error = %v, want ErrUnsupportedDecision", err)
	}
}
