package adapter

import "fmt"

// EnforcementMode states the strongest control an adapter can provide for a
// particular agent hook.
type EnforcementMode string

const (
	EnforcementUnsupported EnforcementMode = "unsupported"
	EnforcementObserveOnly EnforcementMode = "observe_only"
	EnforcementSynchronous EnforcementMode = "synchronous"
)

// HookCapability describes what an adapter can observe and enforce at one
// agent hook. A later manifest contract can serialize these declarations
// without changing the Adapter interface.
type HookCapability struct {
	Hook        string          `json:"hook"`
	Actions     []string        `json:"actions"`
	Enforcement EnforcementMode `json:"enforcement"`
	Decisions   []DecisionKind  `json:"decisions"`
}

// Capabilities is the set of hook-level capabilities declared by an adapter.
type Capabilities struct {
	Hooks []HookCapability `json:"hooks"`
}

// Validate rejects ambiguous or malformed capability declarations.
func (c Capabilities) Validate() error {
	seenHooks := make(map[string]bool, len(c.Hooks))
	for _, hook := range c.Hooks {
		if hook.Hook == "" {
			return fmt.Errorf("%w: hook name is required", ErrInvalidCapabilities)
		}
		if seenHooks[hook.Hook] {
			return fmt.Errorf("%w: duplicate hook %q", ErrInvalidCapabilities, hook.Hook)
		}
		seenHooks[hook.Hook] = true

		switch hook.Enforcement {
		case EnforcementUnsupported, EnforcementObserveOnly, EnforcementSynchronous:
		default:
			return fmt.Errorf("%w: invalid enforcement mode %q", ErrInvalidCapabilities, hook.Enforcement)
		}

		seenActions := make(map[string]bool, len(hook.Actions))
		for _, action := range hook.Actions {
			if action == "" || seenActions[action] {
				return fmt.Errorf("%w: invalid or duplicate action for hook %q", ErrInvalidCapabilities, hook.Hook)
			}
			seenActions[action] = true
		}

		seenDecisions := make(map[DecisionKind]bool, len(hook.Decisions))
		for _, decision := range hook.Decisions {
			if !decision.Valid() || seenDecisions[decision] {
				return fmt.Errorf("%w: invalid or duplicate decision for hook %q", ErrInvalidCapabilities, hook.Hook)
			}
			seenDecisions[decision] = true
		}
	}
	return nil
}

// ForHook returns the declared capability for a hook.
func (c Capabilities) ForHook(name string) (HookCapability, bool) {
	for _, capability := range c.Hooks {
		if capability.Hook == name {
			return capability, true
		}
	}
	return HookCapability{}, false
}

// SupportsAction reports whether a hook declares an action type.
func (h HookCapability) SupportsAction(action string) bool {
	for _, supported := range h.Actions {
		if supported == action {
			return true
		}
	}
	return false
}

// SupportsDecision reports whether a hook can render a decision kind.
func (h HookCapability) SupportsDecision(decision DecisionKind) bool {
	for _, supported := range h.Decisions {
		if supported == decision {
			return true
		}
	}
	return false
}
