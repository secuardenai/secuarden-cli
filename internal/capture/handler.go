package capture

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/secuardenai/secuarden-cli/internal/adapter"
	codexadapter "github.com/secuardenai/secuarden-cli/internal/adapters/codex"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/events"
	"github.com/secuardenai/secuarden-cli/internal/identity"
	"github.com/secuardenai/secuarden-cli/internal/privacy"
	"github.com/secuardenai/secuarden-cli/internal/scope"
	"github.com/secuardenai/secuarden-cli/internal/storage"
	"github.com/secuardenai/secuarden-cli/internal/upload"
)

// Version is set at build time via ldflags.
var Version = "dev"

// maxStdinBytes caps hook input to 10 MiB to bound memory use.
const maxStdinBytes = 10 * 1024 * 1024

// HandleHookEvent reads stdin, processes the hook event, and writes to SQLite.
// It always exits cleanly — errors are logged, never propagated to the caller.
func HandleHookEvent(phase string, version string) {
	if err := handle(phase, version); err != nil {
		logError(err)
	}
}

func handle(phase, version string) error {
	return handleWithParser(phase, version, "claude-code", "anthropic", func(data []byte) (*events.RawHookInput, error) {
		return events.ParseHookInput(data)
	})
}

// HandleCodexHookEvent processes a Codex lifecycle hook using the shared
// persistence pipeline but a separate agent-specific wire parser.
func HandleCodexHookEvent(phase string, version string) {
	if err := handleWithParser(phase, version, "codex", "openai", parseCodexInput); err != nil {
		logError(err)
	}
}

func parseCodexInput(data []byte) (*events.RawHookInput, error) {
	codex, err := events.ParseCodexHookInput(data)
	if err != nil {
		return nil, err
	}
	hookName := codex.HookEventName
	if hookName == "" {
		return nil, fmt.Errorf("Codex hook input: missing hook_event_name")
	}
	codexInput := adapter.RawEvent{Hook: hookName, Payload: data}
	// Capture lifecycle observations are not enforceable action proposals and
	// do not require a tool invocation ID.
	if err := (codexadapter.Adapter{}).Validate(codexInput); err != nil {
		return nil, err
	}
	toolInput, _, err := events.ParseJSONObject(codex.ToolInput)
	if err != nil {
		return nil, fmt.Errorf("parse Codex tool_input: %w", err)
	}
	toolResult, err := events.NormalizeCodexToolResponse(codex.ToolResponse, codex.ToolName)
	if err != nil {
		return nil, fmt.Errorf("parse Codex tool_response: %w", err)
	}
	return &events.RawHookInput{
		SessionID: codex.SessionID, CWD: codex.CWD, ToolName: codex.ToolName,
		ToolUseID: codex.ToolUseID, Model: codex.Model, Prompt: codex.Prompt,
		PermissionMode: codex.PermissionMode, HookEventName: codex.HookEventName,
		Reason: codex.Reason, PermissionStatus: codex.PermissionStatus,
		Timestamp: "", ToolInput: toolInput, ToolInputRaw: codex.ToolInput,
		ToolResponse: toolResult.Fields, ToolResponseRaw: codex.ToolResponse,
		ToolResultStatus: toolResult.ResultStatus, ToolResultSupported: toolResult.Supported,
	}, nil
}

func handleWithParser(phase, version, agentName, provider string, parse func([]byte) (*events.RawHookInput, error)) error {
	if provider != "anthropic" && provider != "openai" {
		return fmt.Errorf("unsupported provider %q", provider)
	}
	// 1. Read one extra byte so oversized input is rejected, not silently truncated.
	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxStdinBytes+1))
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	if len(data) > maxStdinBytes {
		return fmt.Errorf("hook input exceeds %d bytes", maxStdinBytes)
	}
	if len(data) == 0 {
		data = []byte("{}")
	}

	// 2. Compute raw_event_hash before any processing
	rawHash := fmt.Sprintf("%x", sha256.Sum256(data))

	// 3. Parse JSON
	raw, err := parse(data)
	if err != nil {
		return fmt.Errorf("parse input: %w", err)
	}

	// Scope is evaluated before UUID generation, field extraction, file hashing,
	// identity capture, session creation, or event persistence. A skipped hook
	// records only an aggregate diagnostic counter.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	decision := scope.Evaluate(cfg, raw.CWD)
	if !decision.Allowed {
		if err := recordScopeSkip(decision.Reason); err != nil {
			return fmt.Errorf("record scope decision: %w", err)
		}
		return nil
	}

	// Ensure session_id is present
	sessionID := raw.SessionID
	if sessionID == "" {
		sessionID = uuid.New().String()
	}

	// 4. Generate event UUID
	eventID := uuid.New().String()

	// 5. Map tool_name → action_type
	hookPhase := normalizePhase(phase)
	toolName := raw.ToolName
	actionType := mapPhaseToActionForAgent(agentName, hookPhase, toolName)

	// 6. Extract fields
	filePath := events.ExtractFilePath(raw.ToolInput)
	command := events.ExtractCommand(raw.ToolInput)
	diffStats := events.ExtractDiffStats(raw.ToolInput)
	var affectedFiles []events.AffectedFile
	patchLimited := false
	if agentName == "codex" && toolName == "apply_patch" {
		parsed, stats, patchErr := events.ParseApplyPatch(command)
		if patchErr != nil {
			// The patch may contain sensitive material whose paths could not be
			// established. Treat it conservatively and retain no content.
			patchLimited = true
			filePath = ""
			diffStats = ""
		} else {
			affectedFiles = parsed
			filePath = affectedFiles[0].Path
			diffStats = stats
		}
	}
	exitCode := events.ExtractExitCode(raw.ToolResponse)
	outputPreview := events.ExtractOutputPreview(raw.ToolResponse)
	resultStatus := ""
	if hookPhase == events.HookPhasePost {
		if agentName == "codex" {
			resultStatus = raw.ToolResultStatus
			if resultStatus == "" {
				resultStatus = events.ResultUnknown
			}
		} else {
			resultStatus = events.ExtractResultStatus(raw.ToolResponse)
		}
	}

	// MCP server/tool parsing
	var mcpServer, mcpTool string
	if actionType == events.ActionMCPToolUse {
		mcpServer, mcpTool = events.ParseMCPTool(toolName)
	}

	// 7–8. Privacy: sensitive check and/or redaction
	privacyMode := cfg.PrivacyMode
	if privacyMode == "" {
		privacyMode = "redacted_content"
	}
	isSensitive := patchLimited
	var redactedFields []string
	contentHash := computeFileHash(resolveFilePath(raw.CWD, filePath))

	if len(affectedFiles) > 0 {
		for i := range affectedFiles {
			affectedFiles[i].IsSensitive = privacy.IsSensitivePath(resolveFilePath(raw.CWD, affectedFiles[i].Path))
			isSensitive = isSensitive || affectedFiles[i].IsSensitive
		}
	} else if filePath != "" {
		isSensitive = privacy.IsSensitivePath(resolveFilePath(raw.CWD, filePath))
	}

	if isSensitive {
		// Discard all content; keep file_path and content_hash (hash of empty = still useful)
		command = ""
		outputPreview = ""
		redactedFields = []string{"command", "command_output_preview"}
	} else {
		// Redact secrets from text fields
		fieldsToRedact := map[string]string{
			"command":                command,
			"command_output_preview": outputPreview,
		}
		scrubbed, names := privacy.RedactFields(fieldsToRedact)
		command = scrubbed["command"]
		outputPreview = scrubbed["command_output_preview"]
		redactedFields = names
	}
	intentSummary := ""
	if hookPhase == events.HookPhaseIntent && raw.Prompt != "" {
		var intentMatches []string
		intentSummary, intentMatches = privacy.Redact(raw.Prompt)
		if len(intentMatches) > 0 {
			redactedFields = append(redactedFields, "intent_summary")
		}
	}
	if privacyMode == "metadata_only" {
		command = ""
		outputPreview = ""
		diffStats = ""
		intentSummary = ""
		// MCP tool arguments and response content are never mapped. In metadata
		// mode retain only the structural server/tool identifiers.
		redactedFields = []string{}
	}

	// 9. Developer identity (cached after first call for speed)
	cwd := raw.CWD
	var dev *identity.Developer
	if cwd != "" {
		dev = identity.CaptureWithDir(cwd)
	} else {
		dev = identity.Capture()
	}

	// 10. Open database
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return fmt.Errorf("db path: %w", err)
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	// 11. Get or create session
	if err := db.EnsureSession(sessionID, agentName, cwd); err != nil {
		// On session-end: session already exists from session-start; EnsureSession
		// failing here (e.g. SQLITE_BUSY) must not block sync feedback.
		if hookPhase != events.HookPhaseSessionEnd {
			return fmt.Errorf("ensure session: %w", err)
		}
		logError(fmt.Errorf("ensure session (non-fatal on session-end): %w", err))
	}

	// Update session with identity info if we have it.
	// Scrub credentials from git remote URLs before storage — HTTP remotes can
	// contain embedded tokens (https://user:token@host/...).
	if dev != nil {
		gitRepoURL, _ := privacy.Redact(dev.GitRepo)
		_ = db.UpdateSessionIdentity(sessionID, storage.SessionIdentity{
			DeveloperName:  dev.Name,
			DeveloperEmail: dev.Email,
			OSUser:         dev.OSUser,
			MachineID:      dev.MachineID,
			GitBranch:      dev.GitBranch,
			GitRepoURL:     gitRepoURL,
		})
	}

	// 12. Insert event. Storage allocates its per-session sequence atomically
	// with the previous-hash lookup and insert.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	eventTime := raw.Timestamp
	if eventTime == "" {
		eventTime = now
	}
	outcome, permissionStatus, executionStatus := outcomeForPhase(hookPhase, resultStatus)
	if raw.PermissionStatus != "" {
		normalizedPermission, ok := normalizePermissionStatus(raw.PermissionStatus)
		if !ok {
			return fmt.Errorf("invalid permission_status %q", raw.PermissionStatus)
		}
		permissionStatus = normalizedPermission
	}
	if permissionStatus == "denied" {
		outcome = events.ResultRejected
		executionStatus = "not_started"
	}
	completeness := events.Completeness{State: "complete", Reasons: []string{}}
	if patchLimited {
		completeness = events.Completeness{State: "partial", Reasons: []string{"patch_parse_failed"}}
	}
	if agentName == "codex" && hookPhase == events.HookPhasePost && !raw.ToolResultSupported {
		completeness.State = "partial"
		completeness.Reasons = appendUnique(completeness.Reasons, "adapter_field_unavailable")
	}
	if (hookPhase == events.HookPhasePre || hookPhase == events.HookPhasePost) && raw.ToolUseID == "" {
		completeness.State = "partial"
		completeness.Reasons = appendUnique(completeness.Reasons, "missing_invocation_id")
	}

	e := &events.Event{
		Schema:               events.SchemaURL,
		SchemaVersion:        events.SchemaVersion,
		ID:                   eventID,
		SessionID:            sessionID,
		Timestamp:            eventTime,
		CapturedAt:           now,
		InvocationID:         raw.ToolUseID,
		Source:               "secuarden-cli",
		SourceVersion:        version,
		AgentName:            agentName,
		AgentVersion:         raw.AgentVersion,
		Model:                raw.Model,
		Provider:             provider,
		HookPhase:            hookPhase,
		ActionType:           actionType,
		ToolName:             toolName,
		ResultStatus:         resultStatus,
		Outcome:              outcome,
		PermissionStatus:     permissionStatus,
		ExecutionStatus:      executionStatus,
		PrivacyMode:          privacyMode,
		Completeness:         completeness,
		IsSensitive:          isSensitive,
		RedactedFields:       redactedFields,
		FilePath:             filePath,
		AffectedFiles:        affectedFiles,
		ContentHash:          contentHash,
		DiffStats:            diffStats,
		Command:              command,
		ExitCode:             exitCode,
		CommandOutputPreview: outputPreview,
		MCPServer:            mcpServer,
		MCPTool:              mcpTool,
		WorkingDirectory:     cwd,
		RawEventHash:         rawHash,
		IntentSummary:        intentSummary,
	}

	if dev != nil {
		gitRepoURL, _ := privacy.Redact(dev.GitRepo)
		e.DeveloperName = dev.Name
		e.DeveloperEmail = dev.Email
		e.OSUser = dev.OSUser
		e.MachineID = dev.MachineID
		e.GitBranch = dev.GitBranch
		e.GitRepoURL = gitRepoURL
	}
	addCheckpoint(db, e)
	if err := db.WriteEvent(e); err != nil {
		_ = db.RecordCaptureFailure(sessionID, hookPhase, "event_persistence_rejected")
		return err
	}

	// For session_end: write the event first so EndSession sees the correct
	// count, then sync so the SaaS payload reflects the final event_count.
	if hookPhase == events.HookPhaseSessionEnd {
		_ = db.EndSession(sessionID)
		syncOnSessionEnd(sessionID, db)
	}

	return nil
}

func recordScopeSkip(reason string) error {
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return err
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.RecordScopeSkip(reason)
}

func normalizePermissionStatus(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "allowed", "approved":
		return "allowed", true
	case "denied", "rejected":
		return "denied", true
	case "pending":
		return "pending", true
	default:
		return "", false
	}
}

func normalizePhase(phase string) string {
	switch phase {
	case "pre-tool-use":
		return events.HookPhasePre
	case "permission-request":
		return events.HookPhasePre
	case "post-tool-use":
		return events.HookPhasePost
	case "session-start":
		return events.HookPhaseSessionStart
	case "session-end":
		return events.HookPhaseSessionEnd
	case "user-prompt-submit":
		return events.HookPhaseIntent
	case "stop":
		return events.HookPhaseCheckpoint
	default:
		return phase
	}
}

func mapPhaseToAction(phase, toolName string) string {
	return mapPhaseToActionForAgent("claude-code", phase, toolName)
}

func mapPhaseToActionForAgent(agentName, phase, toolName string) string {
	switch phase {
	case events.HookPhaseSessionStart:
		return events.ActionSessionStart
	case events.HookPhaseSessionEnd:
		return events.ActionSessionEnd
	case events.HookPhaseIntent:
		return events.ActionDeveloperIntent
	case events.HookPhaseCheckpoint:
		return events.ActionNotification
	default:
		if agentName == "codex" {
			return events.MapCodexToolToAction(toolName)
		}
		return events.MapToolToAction(toolName)
	}
}

func resolveFilePath(cwd, path string) string {
	if path == "" || filepath.IsAbs(path) || cwd == "" {
		return path
	}
	return filepath.Join(cwd, path)
}

func outcomeForPhase(phase, result string) (string, string, string) {
	switch phase {
	case events.HookPhasePre:
		return "pending", "unknown", "not_started"
	case events.HookPhasePost:
		if result == events.ResultError {
			return "error", "unknown", "failed"
		}
		if result == events.ResultUnknown {
			return "unknown", "unknown", "unknown"
		}
		return "success", "unknown", "completed"
	default:
		return "success", "not_applicable", "completed"
	}
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func computeFileHash(path string) string {
	if path == "" {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// syncOnSessionEnd fires after the local SQLite write on session-end.
// When sync is enabled it POSTs the session summary to the SaaS and prints
// feedback to stdout so the developer sees it before Claude Code exits.
// All errors are swallowed — sync is best-effort and must never block capture.
func syncOnSessionEnd(sessionID string, db *storage.DB) {
	cfg, err := config.Load()
	if err != nil {
		return
	}

	summary, err := db.ReadSessionSummary(sessionID)
	if err != nil {
		logError(fmt.Errorf("sync: read session summary: %w", err))
		return
	}
	if summary.WorkingDirectory == "" {
		return
	}
	resolved, err := config.ForRepository(cfg, summary.WorkingDirectory)
	if err != nil || !resolved.SyncEnabled {
		return
	}

	feedback, err := upload.SyncSession(cfg, summary)
	if err != nil {
		_ = db.RecordSyncFailure(sessionID, err)
		logError(fmt.Errorf("sync: upload: %w", err))
		return
	}
	if err := db.RecordSyncSuccess(sessionID, summary.EventCount); err != nil {
		logError(fmt.Errorf("sync: record success: %w", err))
	}

	if feedback == nil {
		return
	}

	// Always persist — IDE extension users won't see stdout, but will see
	// it via `secuarden status`.
	upload.WriteFeedback(feedback, sessionID)

	// Print to stdout for terminal users (Claude Code CLI or terminal hooks).
	printFeedback(feedback)
}

func printFeedback(f *upload.Feedback) {
	icon := map[string]string{
		"allow":            "✓",
		"warn":             "⚠",
		"require_review":   "⚑",
		"require_evidence": "⚑",
		"block":            "✗",
	}
	mark := icon[f.Decision]
	if mark == "" {
		mark = "·"
	}
	fmt.Printf("\n── Secuarden ──────────────────────────────────────\n")
	fmt.Printf("%s %s\n", mark, f.Summary)
	fmt.Printf("───────────────────────────────────────────────────\n\n")
}

func logError(err error) {
	home, herr := os.UserHomeDir()
	if herr != nil {
		return
	}
	logPath := filepath.Join(home, ".secuarden", "error.log")
	_ = os.MkdirAll(filepath.Dir(logPath), 0700)
	f, ferr := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if ferr != nil {
		return
	}
	defer f.Close()
	logger := log.New(f, "", log.LstdFlags)
	logger.Printf("capture error: %v", err)
}
