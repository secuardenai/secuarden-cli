package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	MaxRawEventPayloadBytes = 10 * 1024 * 1024
	MaxAttributeEntries     = 64
	MaxAttributeBytes       = 1 * 1024 * 1024
	MaxIdentifierLength     = 128
)

var (
	ErrInvalidDescriptor   = errors.New("invalid adapter descriptor")
	ErrInvalidCapabilities = errors.New("invalid adapter capabilities")
	ErrIncompatibleVersion = errors.New("incompatible adapter version")
	ErrInvalidInput        = errors.New("invalid agent input")
	ErrUnsupportedHook     = errors.New("unsupported agent hook")
	ErrUnsupportedAction   = errors.New("unsupported agent action")
	ErrUnsupportedDecision = errors.New("unsupported policy decision")
)

// RawEvent is the untrusted input delivered by an agent integration. Hook is
// supplied by the registered integration entry point rather than inferred from
// Payload.
type RawEvent struct {
	Hook    string          `json:"hook"`
	Payload json.RawMessage `json:"payload"`
}

func (r RawEvent) Validate() error {
	if len(r.Payload) > MaxRawEventPayloadBytes {
		return fmt.Errorf("%w: payload exceeds %d bytes", ErrInvalidInput, MaxRawEventPayloadBytes)
	}
	return nil
}

// ActionProposal is the agent-neutral representation evaluated by the local
// daemon. Attributes must contain only normalized, JSON-compatible values.
type ActionProposal struct {
	SessionID    string                 `json:"session_id"`
	InvocationID string                 `json:"invocation_id"`
	Hook         string                 `json:"hook"`
	ActionType   string                 `json:"action_type"`
	ToolName     string                 `json:"tool_name,omitempty"`
	Attributes   map[string]interface{} `json:"attributes,omitempty"`
}

func (p ActionProposal) Validate() error {
	for name, value := range map[string]string{
		"session_id": p.SessionID, "invocation_id": p.InvocationID,
		"hook": p.Hook, "action_type": p.ActionType, "tool_name": p.ToolName,
	} {
		if value == "" && name != "tool_name" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
		if len(value) > MaxIdentifierLength || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return fmt.Errorf("%w: invalid %s", ErrInvalidInput, name)
		}
	}
	if len(p.Attributes) > MaxAttributeEntries {
		return fmt.Errorf("%w: too many attributes", ErrInvalidInput)
	}
	if len(p.Attributes) > 0 {
		encoded, err := json.Marshal(p.Attributes)
		if err != nil || len(encoded) > MaxAttributeBytes {
			return fmt.Errorf("%w: invalid attributes", ErrInvalidInput)
		}
	}
	return nil
}

// DecisionKind is a control outcome that an adapter may translate back into
// its agent's protocol.
type DecisionKind string

const (
	DecisionAllow           DecisionKind = "allow"
	DecisionDeny            DecisionKind = "deny"
	DecisionRequireApproval DecisionKind = "require_approval"
)

// Valid reports whether the decision belongs to this adapter API version.
func (d DecisionKind) Valid() bool {
	switch d {
	case DecisionAllow, DecisionDeny, DecisionRequireApproval:
		return true
	default:
		return false
	}
}

// PolicyDecision contains the control result to render for the agent. IDs
// correlate the response with policy and evidence records outside the adapter.
type PolicyDecision struct {
	ID       string       `json:"id"`
	Kind     DecisionKind `json:"kind"`
	PolicyID string       `json:"policy_id,omitempty"`
	Reason   string       `json:"reason,omitempty"`
}

// Validate checks the fields common to all agent decision protocols.
func (d PolicyDecision) Validate() error {
	if d.ID == "" {
		return fmt.Errorf("%w: decision id is required", ErrUnsupportedDecision)
	}
	if !d.Kind.Valid() {
		return fmt.Errorf("%w: decision kind %q", ErrUnsupportedDecision, d.Kind)
	}
	return nil
}

// AgentResponse is the adapter-rendered response returned to the agent hook.
// Payload and exit semantics remain agent-specific.
type AgentResponse struct {
	Payload  []byte `json:"payload,omitempty"`
	ExitCode int    `json:"exit_code"`
}
