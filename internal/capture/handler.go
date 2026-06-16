package capture

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/secuarden/secuarden-cli/internal/config"
	"github.com/secuarden/secuarden-cli/internal/events"
	"github.com/secuarden/secuarden-cli/internal/identity"
	"github.com/secuarden/secuarden-cli/internal/privacy"
	"github.com/secuarden/secuarden-cli/internal/storage"
	"github.com/secuarden/secuarden-cli/internal/upload"
)

// Version is set at build time via ldflags.
var Version = "dev"

// HandleHookEvent reads stdin, processes the hook event, and writes to SQLite.
// It always exits cleanly — errors are logged, never propagated to the caller.
func HandleHookEvent(phase string, version string) {
	if err := handle(phase, version); err != nil {
		logError(err)
	}
}

func handle(phase, version string) error {
	// 1. Read all of stdin
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	if len(data) == 0 {
		data = []byte("{}")
	}

	// 2. Compute raw_event_hash before any processing
	rawHash := fmt.Sprintf("%x", sha256.Sum256(data))

	// 3. Parse JSON
	raw, err := events.ParseHookInput(data)
	if err != nil {
		return fmt.Errorf("parse input: %w", err)
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
	actionType := mapPhaseToAction(hookPhase, toolName)

	// 6. Extract fields
	filePath := events.ExtractFilePath(raw.ToolInput)
	command := events.ExtractCommand(raw.ToolInput)
	diffStats := events.ExtractDiffStats(raw.ToolInput)
	exitCode := events.ExtractExitCode(raw.ToolResponse)
	outputPreview := events.ExtractOutputPreview(raw.ToolResponse)
	resultStatus := ""
	if hookPhase == events.HookPhasePost {
		resultStatus = events.ExtractResultStatus(raw.ToolResponse)
	}

	// MCP server/tool parsing
	var mcpServer, mcpTool string
	if actionType == events.ActionMCPToolUse {
		mcpServer, mcpTool = events.ParseMCPTool(toolName)
	}

	// 7–8. Privacy: sensitive check and/or redaction
	isSensitive := false
	var redactedFields []string
	contentHash := computeFileHash(filePath)

	if filePath != "" {
		isSensitive = privacy.IsSensitivePath(filePath)
	}

	if isSensitive {
		// Discard all content; keep file_path and content_hash (hash of empty = still useful)
		command = ""
		outputPreview = ""
		redactedFields = []string{"command", "command_output_preview"}
	} else {
		// Redact secrets from text fields
		fieldsToRedact := map[string]string{
			"command":               command,
			"command_output_preview": outputPreview,
		}
		scrubbed, names := privacy.RedactFields(fieldsToRedact)
		command = scrubbed["command"]
		outputPreview = scrubbed["command_output_preview"]
		redactedFields = names
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
	agentName := "claude-code"
	if err := db.EnsureSession(sessionID, agentName, cwd); err != nil {
		// On session-end: session already exists from session-start; EnsureSession
		// failing here (e.g. SQLITE_BUSY) must not block sync feedback.
		if hookPhase != events.HookPhaseSessionEnd {
			return fmt.Errorf("ensure session: %w", err)
		}
		logError(fmt.Errorf("ensure session (non-fatal on session-end): %w", err))
	}

	// Update session with identity info if we have it
	if dev != nil {
		_ = db.UpdateSession(sessionID, map[string]interface{}{
			"developer_name":  dev.Name,
			"developer_email": dev.Email,
			"os_user":         dev.OSUser,
			"machine_id":      dev.MachineID,
			"git_branch":      dev.GitBranch,
			"git_repo_url":    dev.GitRepo,
		})
	}

	// Special handling for session_end — runs regardless of EnsureSession outcome
	// because the session was already persisted by the session-start hook.
	if hookPhase == events.HookPhaseSessionEnd {
		_ = db.EndSession(sessionID)
		syncOnSessionEnd(sessionID, db)
	}

	// 12. Compute sequence and insert event
	seq, err := db.NextSequence(sessionID)
	if err != nil {
		seq = 1
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	e := &events.Event{
		Schema:        events.SchemaURL,
		SchemaVersion: events.SchemaVersion,
		ID:            eventID,
		SessionID:     sessionID,
		Sequence:      seq,
		Timestamp:     now,
		Source:        "secuarden-cli",
		SourceVersion: version,
		AgentName:     agentName,
		HookPhase:     hookPhase,
		ActionType:    actionType,
		ToolName:      toolName,
		ResultStatus:  resultStatus,
		IsSensitive:   isSensitive,
		RedactedFields: redactedFields,
		FilePath:      filePath,
		ContentHash:   contentHash,
		DiffStats:     diffStats,
		Command:       command,
		ExitCode:      exitCode,
		CommandOutputPreview: outputPreview,
		MCPServer:     mcpServer,
		MCPTool:       mcpTool,
		WorkingDirectory: cwd,
		RawEventHash:  rawHash,
	}

	if dev != nil {
		e.DeveloperName = dev.Name
		e.DeveloperEmail = dev.Email
		e.OSUser = dev.OSUser
		e.MachineID = dev.MachineID
		e.GitBranch = dev.GitBranch
		e.GitRepoURL = dev.GitRepo
	}

	return db.WriteEvent(e)
}

func normalizePhase(phase string) string {
	switch phase {
	case "pre-tool-use":
		return events.HookPhasePre
	case "post-tool-use":
		return events.HookPhasePost
	case "session-start":
		return events.HookPhaseSessionStart
	case "session-end":
		return events.HookPhaseSessionEnd
	default:
		return phase
	}
}

func mapPhaseToAction(phase, toolName string) string {
	switch phase {
	case events.HookPhaseSessionStart:
		return events.ActionSessionStart
	case events.HookPhaseSessionEnd:
		return events.ActionSessionEnd
	default:
		return events.MapToolToAction(toolName)
	}
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
	if err != nil || !cfg.SyncEnabled {
		return
	}

	summary, err := db.ReadSessionSummary(sessionID)
	if err != nil {
		logError(fmt.Errorf("sync: read session summary: %w", err))
		return
	}

	feedback, err := upload.SyncSession(cfg, summary)
	if err != nil {
		logError(fmt.Errorf("sync: upload: %w", err))
		return
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
