package codex

import (
	"encoding/json"
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
	input := adapter.RawEvent{Hook: "PermissionRequest", Payload: json.RawMessage(`{"session_id":"s1","tool_name":"Bash","tool_use_id":"c1","permission_mode":"default","reason":"needs escalation"}`)}
	proposal, err := subject.Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.ActionType != "command_exec" || proposal.Attributes["permission_mode"] != "default" || proposal.Attributes["reason"] != "needs escalation" {
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
	hook := body["hookSpecificOutput"].(map[string]interface{})
	decision := hook["decision"].(map[string]interface{})
	if decision["behavior"] != "deny" || decision["message"] != "repository policy" {
		t.Fatalf("unexpected response: %#v", body)
	}
}
