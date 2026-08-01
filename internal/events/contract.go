package events

import (
	"fmt"
	"strings"
	"time"
)

// ValidateProducerInvariants validates the invariants enforced by this CLI
// before local persistence. It is deliberately not a JSON Schema validator.
func ValidateProducerInvariants(e *Event) error {
	if e.Schema != SchemaURL || e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported evidence contract")
	}
	if e.ID == "" || e.SessionID == "" || e.Sequence < 1 {
		return fmt.Errorf("id, session_id and positive sequence are required")
	}
	if _, err := time.Parse(time.RFC3339Nano, e.Timestamp); err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	if _, err := time.Parse(time.RFC3339Nano, e.CapturedAt); err != nil {
		return fmt.Errorf("invalid captured_at: %w", err)
	}
	if e.Source != "secuarden-cli" || e.SourceVersion == "" || e.AgentName == "" {
		return fmt.Errorf("source identity is required")
	}
	if e.HookPhase == HookPhasePre || e.HookPhase == HookPhasePost {
		if e.ToolName == "" {
			return fmt.Errorf("tool lifecycle events require tool_name")
		}
		missingReason := containsReason(e.Completeness.Reasons, "missing_invocation_id")
		if e.InvocationID == "" && (e.Completeness.State != "partial" || !missingReason) {
			return fmt.Errorf("missing invocation_id requires partial completeness and missing_invocation_id")
		}
		if e.InvocationID != "" && missingReason {
			return fmt.Errorf("missing_invocation_id contradicts present invocation_id")
		}
	} else if containsReason(e.Completeness.Reasons, "missing_invocation_id") {
		return fmt.Errorf("missing_invocation_id applies only to pre/post tool events")
	}
	if e.Outcome == "" || e.PermissionStatus == "" || e.ExecutionStatus == "" {
		return fmt.Errorf("normalized outcome fields are required")
	}
	if e.PrivacyMode != "metadata_only" && e.PrivacyMode != "redacted_content" {
		return fmt.Errorf("invalid privacy_mode")
	}
	if e.PrivacyMode == "metadata_only" && (e.Command != "" || e.CommandOutputPreview != "" || e.IntentSummary != "") {
		return fmt.Errorf("metadata_only contains content")
	}
	if e.RawEventHash == "" || len(e.RawEventHash) != 64 || strings.Trim(e.RawEventHash, "0123456789abcdef") != "" {
		return fmt.Errorf("raw_event_hash must be lowercase sha256")
	}
	if e.Completeness.State != "complete" && e.Completeness.State != "partial" {
		return fmt.Errorf("invalid completeness state")
	}
	if e.Completeness.State == "complete" && len(e.Completeness.Reasons) != 0 {
		return fmt.Errorf("complete evidence cannot have completeness reasons")
	}
	if e.Completeness.State == "partial" && len(e.Completeness.Reasons) == 0 {
		return fmt.Errorf("partial evidence requires a completeness reason")
	}
	return nil
}

func containsReason(reasons []string, wanted string) bool {
	for _, reason := range reasons {
		if reason == wanted {
			return true
		}
	}
	return false
}
