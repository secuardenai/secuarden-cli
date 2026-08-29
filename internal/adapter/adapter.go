// Package adapter defines the versioned contract implemented by agent-specific
// adapters. It contains no agent discovery, transport, policy, or storage logic.
package adapter

import "fmt"

// APIVersion is the adapter interface version understood by this CLI.
const APIVersion = "1.0.0"

// Adapter translates between one agent family's protocol and Secuarden's
// agent-neutral action and decision types.
//
// Implementations must be deterministic and side-effect free. Installation,
// daemon communication, policy evaluation, and evidence persistence belong to
// callers outside this interface.
type Adapter interface {
	Descriptor() Descriptor
	Capabilities() Capabilities
	Validate(input RawEvent) error
	Normalize(input RawEvent) (ActionProposal, error)
	RenderDecision(proposal ActionProposal, decision PolicyDecision) (AgentResponse, error)
}

// Descriptor identifies an adapter implementation and the agent family it
// supports. APIVersion versions this interface; Version versions the adapter
// implementation independently.
type Descriptor struct {
	APIVersion  string `json:"api_version"`
	ID          string `json:"id"`
	Version     string `json:"version"`
	AgentFamily string `json:"agent_family"`
}

// Validate checks the identity fields required at the adapter boundary.
func (d Descriptor) Validate() error {
	if d.APIVersion != APIVersion {
		return fmt.Errorf("%w: adapter API version %q", ErrIncompatibleVersion, d.APIVersion)
	}
	if d.ID == "" {
		return fmt.Errorf("%w: adapter id is required", ErrInvalidDescriptor)
	}
	if d.Version == "" {
		return fmt.Errorf("%w: adapter version is required", ErrInvalidDescriptor)
	}
	if d.AgentFamily == "" {
		return fmt.Errorf("%w: agent family is required", ErrInvalidDescriptor)
	}
	return nil
}
