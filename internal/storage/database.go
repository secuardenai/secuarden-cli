package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/events"
	_ "modernc.org/sqlite"
)

// DB wraps the SQLite connection.
type DB struct {
	db *sql.DB
}

// DefaultDBPath returns ~/.secuarden/secuarden.db
func DefaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".secuarden", "secuarden.db"), nil
}

// Open opens (or creates) the SQLite database at path and applies the schema.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// modernc.org/sqlite ignores mattn-style DSN params. Apply pragmas explicitly.
	// WAL allows concurrent readers + one writer across processes.
	// Set busy_timeout before journal_mode: selecting WAL can itself encounter
	// a lock held by another hook opening the same database.
	for _, pragma := range []string{
		"PRAGMA busy_timeout=5000",
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("pragma %q: %w", pragma, err)
		}
	}

	if _, err := db.Exec(sqlSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	// Additive migrations for databases created by earlier CLI releases.
	for _, migration := range []string{
		"ALTER TABLE events ADD COLUMN previous_event_hash TEXT",
		"ALTER TABLE events ADD COLUMN event_hash TEXT",
		"ALTER TABLE sessions ADD COLUMN session_hash TEXT",
		"ALTER TABLE events ADD COLUMN captured_at TEXT",
		"ALTER TABLE events ADD COLUMN schema_version TEXT",
		"ALTER TABLE events ADD COLUMN invocation_id TEXT",
		"ALTER TABLE events ADD COLUMN agent_version TEXT",
		"ALTER TABLE events ADD COLUMN model TEXT",
		"ALTER TABLE events ADD COLUMN provider TEXT",
		"ALTER TABLE events ADD COLUMN outcome TEXT",
		"ALTER TABLE events ADD COLUMN permission_status TEXT",
		"ALTER TABLE events ADD COLUMN execution_status TEXT",
		"ALTER TABLE events ADD COLUMN privacy_mode TEXT",
		"ALTER TABLE events ADD COLUMN completeness_state TEXT",
		"ALTER TABLE events ADD COLUMN completeness_reasons TEXT",
		"ALTER TABLE events ADD COLUMN affected_files TEXT",
		// Preserve evidence from the public worktree's historical collector format.
		"ALTER TABLE events ADD COLUMN collector_details TEXT",
		"ALTER TABLE events ADD COLUMN repository_checkpoint TEXT",
		"ALTER TABLE sessions ADD COLUMN capture_failure_count INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE sessions ADD COLUMN completeness_state TEXT NOT NULL DEFAULT 'complete'",
		"ALTER TABLE sessions ADD COLUMN completeness_reasons TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE sessions ADD COLUMN privacy_mode TEXT NOT NULL DEFAULT 'redacted_content'",
	} {
		if _, err := db.Exec(migration); err != nil && !isDuplicateColumnError(err) {
			db.Close()
			return nil, fmt.Errorf("migrate schema: %w", err)
		}
	}
	if _, err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_events_hash ON events(event_hash) WHERE event_hash IS NOT NULL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("create event hash index: %w", err)
	}
	var duplicateSession string
	var duplicateSequence, duplicateCount int
	err = db.QueryRow(`SELECT session_id, sequence, COUNT(*)
		FROM events GROUP BY session_id, sequence HAVING COUNT(*) > 1
		ORDER BY session_id, sequence LIMIT 1`).
		Scan(&duplicateSession, &duplicateSequence, &duplicateCount)
	if err != nil && err != sql.ErrNoRows {
		db.Close()
		return nil, fmt.Errorf("inspect event sequence migration: %w", err)
	}
	if err == nil {
		db.Close()
		return nil, fmt.Errorf(
			"cannot create unique event sequence index: session %q sequence %d has %d captured events; no events were removed, resolve the duplicate rows before reopening",
			duplicateSession, duplicateSequence, duplicateCount,
		)
	}
	if _, err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_events_session_sequence ON events(session_id, sequence)"); err != nil {
		db.Close()
		return nil, fmt.Errorf("create unique event sequence index: %w", err)
	}

	return &DB{db: db}, nil
}

func isDuplicateColumnError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "duplicate column")
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// RecordScopeSkip increments a non-sensitive diagnostic counter. It never
// stores the hook payload, session ID, working directory, or repository path.
func (d *DB) RecordScopeSkip(reason string) error {
	switch reason {
	case "missing_working_directory", "unresolvable_working_directory", "non_git_directory", "different_repository", "unapproved_repository":
	default:
		return fmt.Errorf("invalid scope skip reason")
	}
	key := "scope_skip_" + reason
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := d.db.Exec(`
		INSERT INTO metadata (key, value, updated_at) VALUES (?, '1', ?)
		ON CONFLICT(key) DO UPDATE SET value = CAST(metadata.value AS INTEGER) + 1, updated_at = excluded.updated_at`, key, now)
	return err
}

// ScopeSkipCounts returns aggregate scope diagnostics without exposing event
// data or paths.
func (d *DB) ScopeSkipCounts() (map[string]int, error) {
	rows, err := d.db.Query(`SELECT key, value FROM metadata WHERE key LIKE 'scope_skip_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make(map[string]int)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		count, err := strconv.Atoi(value)
		if err != nil {
			continue
		}
		counts[strings.TrimPrefix(key, "scope_skip_")] = count
	}
	return counts, rows.Err()
}

// EnsureSession creates a session row if it doesn't exist. Returns the session ID.
func (d *DB) EnsureSession(sessionID, agentName, workingDir string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	sessionHash, err := computeSessionHash(sessionIntegrityRecord{
		ID: sessionID, AgentName: agentName, WorkingDirectory: workingDir,
	})
	if err != nil {
		return fmt.Errorf("hash session: %w", err)
	}
	_, err = d.db.Exec(`
		INSERT OR IGNORE INTO sessions (id, agent_name, working_directory, started_at, session_hash)
		VALUES (?, ?, ?, ?, ?)`,
		sessionID, agentName, workingDir, now, sessionHash,
	)
	return err
}

// EndSession marks a session as ended and updates event_count.
func (d *DB) EndSession(sessionID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.db.Exec(`
		UPDATE sessions SET ended_at = ?,
		event_count = (SELECT COUNT(*) FROM events WHERE session_id = ?)
		WHERE id = ?`,
		now, sessionID, sessionID,
	)
	if err != nil {
		return err
	}
	return d.ReconcileSessionCompleteness(sessionID)
}

// RecordCaptureFailure stores only a safe category, never hook payload or raw
// error text, and makes the failure visible on the associated session.
func (d *DB) RecordCaptureFailure(sessionID, hookPhase, category string) error {
	switch category {
	case "event_persistence_rejected", "capture_error":
	default:
		category = "capture_error"
	}
	switch hookPhase {
	case events.HookPhasePre, events.HookPhasePost, events.HookPhaseSessionStart, events.HookPhaseSessionEnd, events.HookPhaseIntent, events.HookPhaseCheckpoint:
	default:
		hookPhase = "unknown"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO capture_failures(session_id, hook_phase, category, occurred_at) VALUES(NULLIF(?,''),?,?,?)`, sessionID, hookPhase, category, now); err != nil {
		return err
	}
	if sessionID != "" {
		if _, err = tx.Exec(`UPDATE sessions SET capture_failure_count=capture_failure_count+1, completeness_state='partial', completeness_reasons='["capture_error"]' WHERE id=?`, sessionID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ReconcileSessionCompleteness derives missing lifecycle halves and capture failures.
func (d *DB) ReconcileSessionCompleteness(sessionID string) error {
	reasons := map[string]bool{}
	rows, err := d.db.Query(`SELECT COALESCE(invocation_id,''), hook_phase, COALESCE(completeness_reasons,'[]') FROM events WHERE session_id=?`, sessionID)
	if err != nil {
		return err
	}
	pairs := map[string]map[string]bool{}
	for rows.Next() {
		var invocation, phase, encoded string
		if err := rows.Scan(&invocation, &phase, &encoded); err != nil {
			rows.Close()
			return err
		}
		var eventReasons []string
		_ = json.Unmarshal([]byte(encoded), &eventReasons)
		for _, reason := range eventReasons {
			reasons[reason] = true
		}
		if invocation != "" && (phase == "pre" || phase == "post") {
			if pairs[invocation] == nil {
				pairs[invocation] = map[string]bool{}
			}
			pairs[invocation][phase] = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, phases := range pairs {
		if !phases["pre"] {
			reasons["missing_pre_event"] = true
		}
		if !phases["post"] {
			reasons["missing_post_event"] = true
		}
	}
	var failures int
	if err := d.db.QueryRow(`SELECT capture_failure_count FROM sessions WHERE id=?`, sessionID).Scan(&failures); err != nil {
		return err
	}
	if failures > 0 {
		reasons["capture_error"] = true
	}
	ordered := []string{"missing_invocation_id", "missing_pre_event", "missing_post_event", "capture_error"}
	result := make([]string, 0, len(reasons))
	for _, reason := range ordered {
		if reasons[reason] {
			result = append(result, reason)
			delete(reasons, reason)
		}
	}
	for reason := range reasons {
		result = append(result, reason)
	}
	state := "complete"
	if len(result) > 0 {
		state = "partial"
	}
	encoded, _ := json.Marshal(result)
	_, err = d.db.Exec(`UPDATE sessions SET completeness_state=?, completeness_reasons=? WHERE id=?`, state, string(encoded), sessionID)
	return err
}

// SessionIdentity holds developer and git identity fields written to a session row.
type SessionIdentity struct {
	DeveloperName  string
	DeveloperEmail string
	OSUser         string
	MachineID      string
	GitBranch      string
	GitRepoURL     string
}

// UpdateSessionIdentity writes developer and git identity fields for a session.
// Uses a fully static SQL statement — no column name is ever interpolated.
func (d *DB) UpdateSessionIdentity(sessionID string, id SessionIdentity) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin session identity update: %w", err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`
		UPDATE sessions SET
			developer_name  = ?,
			developer_email = ?,
			os_user         = ?,
			machine_id      = ?,
			git_branch      = ?,
			git_repo_url    = ?
		WHERE id = ?`,
		nullStr(id.DeveloperName), nullStr(id.DeveloperEmail),
		nullStr(id.OSUser), nullStr(id.MachineID),
		nullStr(id.GitBranch), nullStr(id.GitRepoURL),
		sessionID,
	); err != nil {
		return err
	}
	if err := updateSessionHash(tx, sessionID); err != nil {
		return err
	}
	return tx.Commit()
}

// WriteEvent atomically allocates the per-session sequence, reads the previous
// hash, hashes the event, and inserts it under an SQLite immediate transaction.
func (d *DB) WriteEvent(e *events.Event) error {
	redactedJSON, err := json.Marshal(e.RedactedFields)
	if err != nil {
		redactedJSON = []byte("[]")
	}
	completenessJSON, _ := json.Marshal(e.Completeness.Reasons)
	affectedFilesJSON, err := json.Marshal(e.AffectedFiles)
	if err != nil {
		return fmt.Errorf("encode affected file evidence: %w", err)
	}
	checkpointJSON, err := json.Marshal(e.RepositoryCheckpoint)
	if err != nil {
		return err
	}
	storedSchemaVersion := ""
	if e.CapturedAt != "" {
		storedSchemaVersion = e.SchemaVersion
	}

	var exitCode *int
	if e.ExitCode != nil {
		exitCode = e.ExitCode
	}

	var durationMS *int64
	if e.DurationMS != nil {
		durationMS = e.DurationMS
	}

	sensitive := 0
	if e.IsSensitive {
		sensitive = 1
	}

	ctx := context.Background()
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire event write connection: %w", err)
	}
	defer conn.Close()

	// PRAGMAs are connection-local. Apply the configured timeout to the pinned
	// connection before BEGIN IMMEDIATE obtains SQLite's reserved writer lock.
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout=5000"); err != nil {
		return fmt.Errorf("configure event write busy timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return fmt.Errorf("configure event write foreign keys: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return eventWriteError("begin immediate event write", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	var sequence int
	var previousHash string
	if err := conn.QueryRowContext(ctx, `SELECT
		COALESCE(MAX(sequence), 0) + 1,
		COALESCE((
			SELECT event_hash FROM events
			WHERE session_id = ? ORDER BY sequence DESC, id DESC LIMIT 1
		), '')
		FROM events WHERE session_id = ?`, e.SessionID, e.SessionID).
		Scan(&sequence, &previousHash); err != nil {
		return fmt.Errorf("allocate event sequence: %w", err)
	}
	e.Sequence = sequence
	if c := e.RepositoryCheckpoint; c != nil && c.PreviousSequence != sequence-1 {
		c.Status = "partial"
		c.Reasons = append(c.Reasons, "concurrent_capture")
		for i := range c.Files {
			if c.Files[i].Attribution == "agent_associated" {
				c.Files[i].Attribution = "human_or_unattributed"
			}
		}
		e.Completeness.State = "partial"
		found := false
		for _, reason := range e.Completeness.Reasons {
			if reason == "repository_checkpoint_incomplete" {
				found = true
			}
		}
		if !found {
			e.Completeness.Reasons = append(e.Completeness.Reasons, "repository_checkpoint_incomplete")
		}
		checkpointJSON, _ = json.Marshal(c)
		completenessJSON, _ = json.Marshal(e.Completeness.Reasons)
	}
	if e.CapturedAt != "" {
		if err := events.ValidateProducerInvariants(e); err != nil {
			return fmt.Errorf("event does not satisfy Stage 1 evidence contract: %w", err)
		}
	}
	hashingEvent := *e
	hashingEvent.SchemaVersion = storedSchemaVersion
	eventHash, err := computeCheckpointEventHash(previousHash, &hashingEvent, string(redactedJSON), string(affectedFilesJSON), string(checkpointJSON))
	if err != nil {
		return fmt.Errorf("hash event: %w", err)
	}
	_, err = conn.ExecContext(ctx, `
		INSERT INTO events (
			id, session_id, sequence, timestamp,
			source, source_version,
			agent_name, hook_phase, action_type, tool_name,
			result_status,
			is_sensitive, redacted_fields,
			file_path, affected_files, content_hash, diff_stats,
			command, exit_code, command_output_preview,
			mcp_server, mcp_tool,
			duration_ms,
			working_directory, git_branch,
			developer_email, intent_summary, raw_event_hash,
			previous_event_hash, event_hash
		) VALUES (
			?,?,?,?,
			?,?,
			?,?,?,?,
			?,
			?,?,
			?,?,?,?,
			?,?,?,
			?,?,
			?,
			?,?,
			?,?,?,?,?
		)`,
		e.ID, e.SessionID, e.Sequence, e.Timestamp,
		e.Source, e.SourceVersion,
		e.AgentName, e.HookPhase, e.ActionType, e.ToolName,
		nullStr(e.ResultStatus),
		sensitive, string(redactedJSON),
		nullStr(e.FilePath), string(affectedFilesJSON), nullStr(e.ContentHash), nullStr(e.DiffStats),
		nullStr(e.Command), exitCode, nullStr(e.CommandOutputPreview),
		nullStr(e.MCPServer), nullStr(e.MCPTool),
		durationMS,
		nullStr(e.WorkingDirectory), nullStr(e.GitBranch),
		nullStr(e.DeveloperEmail), nullStr(e.IntentSummary), nullStr(e.RawEventHash),
		nullStr(previousHash), eventHash,
	)
	if err != nil {
		return eventWriteError("insert event", err)
	}
	if _, err := conn.ExecContext(ctx, `UPDATE events SET repository_checkpoint=?, schema_version=?, captured_at=?, invocation_id=?, agent_version=?, model=?, provider=?,
		outcome=?, permission_status=?, execution_status=?, privacy_mode=?, completeness_state=?, completeness_reasons=? WHERE id=?`,
		string(checkpointJSON), nullStr(storedSchemaVersion), nullStr(e.CapturedAt), nullStr(e.InvocationID), nullStr(e.AgentVersion), nullStr(e.Model), nullStr(e.Provider),
		nullStr(e.Outcome), nullStr(e.PermissionStatus), nullStr(e.ExecutionStatus), nullStr(e.PrivacyMode),
		nullStr(e.Completeness.State), string(completenessJSON), e.ID); err != nil {
		return eventWriteError("store Stage 1 evidence fields", err)
	}

	// Keep event_count in sessions up to date
	if _, err := conn.ExecContext(ctx,
		`UPDATE sessions SET event_count = event_count + 1, privacy_mode=?,
		 completeness_state=CASE WHEN ?='partial' THEN 'partial' ELSE completeness_state END,
		 completeness_reasons=CASE WHEN ?='partial' THEN ? ELSE completeness_reasons END WHERE id = ?`,
		e.PrivacyMode, e.Completeness.State, e.Completeness.State, string(completenessJSON), e.SessionID,
	); err != nil {
		return eventWriteError("update session event count", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return eventWriteError("commit event write", err)
	}
	committed = true
	return nil
}

func eventWriteError(operation string, err error) error {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "database is locked") || strings.Contains(message, "database is busy") ||
		strings.Contains(message, "sqlite_busy") {
		return fmt.Errorf("%s: SQLite write contention exceeded 5s busy timeout: %w", operation, err)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

const (
	eventHashPrefix       = "v4:"
	legacyEventHashPrefix = "v3:"
	sessionHashPrefix     = "s1:"
)

// eventIntegrityRecordV2 is the canonical representation of every
// security-relevant event value persisted in the events table. New fields must
// be introduced in a new format version rather than changing this structure.
type eventIntegrityRecordV2 struct {
	FormatVersion        int    `json:"format_version"`
	PreviousEventHash    string `json:"previous_event_hash"`
	ID                   string `json:"id"`
	SessionID            string `json:"session_id"`
	Sequence             int    `json:"sequence"`
	Timestamp            string `json:"timestamp"`
	SchemaVersion        string `json:"schema_version"`
	CapturedAt           string `json:"captured_at"`
	InvocationID         string `json:"invocation_id"`
	Source               string `json:"source"`
	SourceVersion        string `json:"source_version"`
	AgentName            string `json:"agent_name"`
	AgentVersion         string `json:"agent_version"`
	Model                string `json:"model"`
	Provider             string `json:"provider"`
	HookPhase            string `json:"hook_phase"`
	ActionType           string `json:"action_type"`
	ToolName             string `json:"tool_name"`
	ResultStatus         string `json:"result_status"`
	Outcome              string `json:"outcome"`
	PermissionStatus     string `json:"permission_status"`
	ExecutionStatus      string `json:"execution_status"`
	PrivacyMode          string `json:"privacy_mode"`
	CompletenessState    string `json:"completeness_state"`
	CompletenessReasons  string `json:"completeness_reasons"`
	IsSensitive          bool   `json:"is_sensitive"`
	RedactedFields       string `json:"redacted_fields"`
	FilePath             string `json:"file_path"`
	ContentHash          string `json:"content_hash"`
	DiffStats            string `json:"diff_stats"`
	Command              string `json:"command"`
	ExitCode             *int   `json:"exit_code"`
	CommandOutputPreview string `json:"command_output_preview"`
	MCPServer            string `json:"mcp_server"`
	MCPTool              string `json:"mcp_tool"`
	DurationMS           *int64 `json:"duration_ms"`
	WorkingDirectory     string `json:"working_directory"`
	GitBranch            string `json:"git_branch"`
	DeveloperEmail       string `json:"developer_email"`
	IntentSummary        string `json:"intent_summary"`
	RawEventHash         string `json:"raw_event_hash"`
}

func computeEventHashV2(previous string, e *events.Event, redactedFields string) (string, error) {
	completenessReasons, _ := json.Marshal(e.Completeness.Reasons)
	return hashCanonicalJSON(legacyEventHashPrefix, eventIntegrityRecordV2{
		FormatVersion: 2, PreviousEventHash: previous,
		ID: e.ID, SessionID: e.SessionID, Sequence: e.Sequence, Timestamp: e.Timestamp, SchemaVersion: e.SchemaVersion,
		CapturedAt: e.CapturedAt, InvocationID: e.InvocationID,
		Source: e.Source, SourceVersion: e.SourceVersion, AgentName: e.AgentName,
		AgentVersion: e.AgentVersion, Model: e.Model, Provider: e.Provider,
		HookPhase: e.HookPhase, ActionType: e.ActionType, ToolName: e.ToolName,
		ResultStatus: e.ResultStatus, Outcome: e.Outcome, PermissionStatus: e.PermissionStatus,
		ExecutionStatus: e.ExecutionStatus, PrivacyMode: e.PrivacyMode,
		CompletenessState: e.Completeness.State, CompletenessReasons: string(completenessReasons), IsSensitive: e.IsSensitive,
		RedactedFields: redactedFields, FilePath: e.FilePath, ContentHash: e.ContentHash,
		DiffStats: e.DiffStats, Command: e.Command, ExitCode: e.ExitCode,
		CommandOutputPreview: e.CommandOutputPreview, MCPServer: e.MCPServer,
		MCPTool: e.MCPTool, DurationMS: e.DurationMS, WorkingDirectory: e.WorkingDirectory,
		GitBranch: e.GitBranch, DeveloperEmail: e.DeveloperEmail,
		IntentSummary: e.IntentSummary, RawEventHash: e.RawEventHash,
	})
}

type eventIntegrityRecordV3 struct {
	eventIntegrityRecordV2
	AffectedFiles string `json:"affected_files"`
}

func computeEventHashV3(previous string, e *events.Event, redactedFields, affectedFiles string) (string, error) {
	completenessReasons, _ := json.Marshal(e.Completeness.Reasons)
	base := eventIntegrityRecordV2{
		FormatVersion: 3, PreviousEventHash: previous,
		ID: e.ID, SessionID: e.SessionID, Sequence: e.Sequence, Timestamp: e.Timestamp, SchemaVersion: e.SchemaVersion,
		CapturedAt: e.CapturedAt, InvocationID: e.InvocationID,
		Source: e.Source, SourceVersion: e.SourceVersion, AgentName: e.AgentName,
		AgentVersion: e.AgentVersion, Model: e.Model, Provider: e.Provider,
		HookPhase: e.HookPhase, ActionType: e.ActionType, ToolName: e.ToolName,
		ResultStatus: e.ResultStatus, Outcome: e.Outcome, PermissionStatus: e.PermissionStatus,
		ExecutionStatus: e.ExecutionStatus, PrivacyMode: e.PrivacyMode,
		CompletenessState: e.Completeness.State, CompletenessReasons: string(completenessReasons), IsSensitive: e.IsSensitive,
		RedactedFields: redactedFields, FilePath: e.FilePath, ContentHash: e.ContentHash,
		DiffStats: e.DiffStats, Command: e.Command, ExitCode: e.ExitCode,
		CommandOutputPreview: e.CommandOutputPreview, MCPServer: e.MCPServer,
		MCPTool: e.MCPTool, DurationMS: e.DurationMS, WorkingDirectory: e.WorkingDirectory,
		GitBranch: e.GitBranch, DeveloperEmail: e.DeveloperEmail,
		IntentSummary: e.IntentSummary, RawEventHash: e.RawEventHash,
	}
	return hashCanonicalJSON(eventHashPrefix, eventIntegrityRecordV3{eventIntegrityRecordV2: base, AffectedFiles: affectedFiles})
}

// sessionIntegrityRecord protects the session context consumed by provenance
// reporting and secuarden gate.
type sessionIntegrityRecord struct {
	FormatVersion    int    `json:"format_version"`
	ID               string `json:"id"`
	AgentName        string `json:"agent_name"`
	AgentVersion     string `json:"agent_version"`
	Model            string `json:"model"`
	DeveloperName    string `json:"developer_name"`
	DeveloperEmail   string `json:"developer_email"`
	OSUser           string `json:"os_user"`
	MachineID        string `json:"machine_id"`
	WorkingDirectory string `json:"working_directory"`
	GitRepoURL       string `json:"git_repo_url"`
	GitBranch        string `json:"git_branch"`
}

func computeSessionHash(record sessionIntegrityRecord) (string, error) {
	record.FormatVersion = 1
	return hashCanonicalJSON(sessionHashPrefix, record)
}

func hashCanonicalJSON(prefix string, value interface{}) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return prefix + fmt.Sprintf("%x", sum[:]), nil
}

func readSessionIntegrityRecord(row *sql.Row) (sessionIntegrityRecord, string, error) {
	var record sessionIntegrityRecord
	var storedHash string
	err := row.Scan(
		&record.ID, &record.AgentName, &record.AgentVersion, &record.Model,
		&record.DeveloperName, &record.DeveloperEmail, &record.OSUser,
		&record.MachineID, &record.WorkingDirectory, &record.GitRepoURL,
		&record.GitBranch, &storedHash,
	)
	return record, storedHash, err
}

const sessionIntegritySelect = `SELECT id, agent_name,
	COALESCE(agent_version, ''), COALESCE(model, ''),
	COALESCE(developer_name, ''), COALESCE(developer_email, ''),
	COALESCE(os_user, ''), COALESCE(machine_id, ''),
	COALESCE(working_directory, ''), COALESCE(git_repo_url, ''),
	COALESCE(git_branch, ''), COALESCE(session_hash, '')
	FROM sessions WHERE id = ?`

func updateSessionHash(tx *sql.Tx, sessionID string) error {
	record, _, err := readSessionIntegrityRecord(tx.QueryRow(sessionIntegritySelect, sessionID))
	if err != nil {
		return fmt.Errorf("read session for hashing: %w", err)
	}
	hash, err := computeSessionHash(record)
	if err != nil {
		return fmt.Errorf("hash session: %w", err)
	}
	if _, err := tx.Exec("UPDATE sessions SET session_hash = ? WHERE id = ?", hash, sessionID); err != nil {
		return fmt.Errorf("store session hash: %w", err)
	}
	return nil
}

// IntegrityResult describes verification of the append-only event hash chains.
type IntegrityResult struct {
	Valid           bool     `json:"valid"`
	EventsChecked   int      `json:"events_checked"`
	SessionsChecked int      `json:"sessions_checked"`
	LegacyEvents    int      `json:"legacy_events"`
	LegacySessions  int      `json:"legacy_sessions"`
	Failures        []string `json:"failures,omitempty"`
}

type ProvenanceRecord struct {
	EventID     string `json:"event_id"`
	SessionID   string `json:"session_id"`
	Timestamp   string `json:"timestamp"`
	FilePath    string `json:"file_path"`
	ContentHash string `json:"content_hash,omitempty"`
	Agent       string `json:"agent"`
	Model       string `json:"model,omitempty"`
	Developer   string `json:"developer,omitempty"`
	Repository  string `json:"repository,omitempty"`
	Branch      string `json:"branch,omitempty"`
	IsSensitive bool   `json:"is_sensitive"`
	EventHash   string `json:"event_hash,omitempty"`
}

func (d *DB) ListWriteProvenance(since time.Time) ([]ProvenanceRecord, error) {
	rows, err := d.db.Query(`SELECT e.id, e.session_id, e.timestamp,
		COALESCE(json_extract(files.value, '$.path'), e.file_path, ''),
		CASE WHEN files.value IS NULL OR json_extract(files.value, '$.path') = e.file_path THEN COALESCE(e.content_hash, '') ELSE '' END,
		e.agent_name, COALESCE(s.model, ''), COALESCE(s.developer_email, ''),
		COALESCE(s.git_repo_url, ''), COALESCE(s.git_branch, ''),
		COALESCE(json_extract(files.value, '$.is_sensitive'), e.is_sensitive), COALESCE(e.event_hash, '')
		FROM events e JOIN sessions s ON s.id=e.session_id
		LEFT JOIN json_each(COALESCE(e.affected_files, '[]')) files
		WHERE e.action_type='file_write' AND e.hook_phase='post' AND e.timestamp >= ?
		  AND e.outcome = 'success'
		  AND e.execution_status = 'completed'
		ORDER BY e.timestamp`, since.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []ProvenanceRecord
	for rows.Next() {
		var r ProvenanceRecord
		var sensitive int
		if err := rows.Scan(&r.EventID, &r.SessionID, &r.Timestamp, &r.FilePath,
			&r.ContentHash, &r.Agent, &r.Model, &r.Developer, &r.Repository,
			&r.Branch, &sensitive, &r.EventHash); err != nil {
			return nil, err
		}
		r.IsSensitive = sensitive == 1
		records = append(records, r)
	}
	return records, rows.Err()
}

// VerifyIntegrity recomputes every session chain without reading source files.
func (d *DB) VerifyIntegrity() (*IntegrityResult, error) {
	rows, err := d.db.Query(`SELECT id, session_id, sequence, timestamp, COALESCE(schema_version, ''),
		COALESCE(captured_at, ''), COALESCE(invocation_id, ''),
		source, COALESCE(source_version, ''), agent_name,
		COALESCE(agent_version, ''), COALESCE(model, ''), COALESCE(provider, ''), hook_phase, action_type,
		COALESCE(tool_name, ''), COALESCE(result_status, ''), is_sensitive,
		COALESCE(outcome, ''), COALESCE(permission_status, ''), COALESCE(execution_status, ''),
		COALESCE(privacy_mode, ''), COALESCE(completeness_state, ''), COALESCE(completeness_reasons, '[]'),
		COALESCE(redacted_fields, 'null'), COALESCE(file_path, ''), COALESCE(affected_files, 'null'),
		COALESCE(content_hash, ''), COALESCE(diff_stats, ''),
		COALESCE(command, ''), exit_code, COALESCE(command_output_preview, ''),
		COALESCE(mcp_server, ''), COALESCE(mcp_tool, ''), duration_ms,
		COALESCE(working_directory, ''), COALESCE(git_branch, ''),
		COALESCE(developer_email, ''), COALESCE(intent_summary, ''),
		COALESCE(raw_event_hash, ''),
		COALESCE(previous_event_hash, ''), COALESCE(event_hash, ''), COALESCE(repository_checkpoint, 'null'), COALESCE(collector_details, '')
		FROM events ORDER BY session_id, sequence, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := &IntegrityResult{Valid: true}
	previous := map[string]string{}
	for rows.Next() {
		var e events.Event
		var redactedFields, affectedFiles, completenessReasons, storedPrevious, storedHash, checkpoint, collectorDetails string
		var sensitive int
		var exitCode, durationMS sql.NullInt64
		if err := rows.Scan(
			&e.ID, &e.SessionID, &e.Sequence, &e.Timestamp, &e.SchemaVersion, &e.CapturedAt, &e.InvocationID, &e.Source,
			&e.SourceVersion, &e.AgentName, &e.AgentVersion, &e.Model, &e.Provider, &e.HookPhase, &e.ActionType,
			&e.ToolName, &e.ResultStatus, &sensitive, &e.Outcome, &e.PermissionStatus, &e.ExecutionStatus,
			&e.PrivacyMode, &e.Completeness.State, &completenessReasons, &redactedFields,
			&e.FilePath, &affectedFiles, &e.ContentHash, &e.DiffStats, &e.Command, &exitCode,
			&e.CommandOutputPreview, &e.MCPServer, &e.MCPTool, &durationMS,
			&e.WorkingDirectory, &e.GitBranch, &e.DeveloperEmail,
			&e.IntentSummary, &e.RawEventHash, &storedPrevious, &storedHash, &checkpoint, &collectorDetails,
		); err != nil {
			return nil, err
		}
		e.IsSensitive = sensitive == 1
		_ = json.Unmarshal([]byte(completenessReasons), &e.Completeness.Reasons)
		_ = json.Unmarshal([]byte(affectedFiles), &e.AffectedFiles)
		if exitCode.Valid {
			value := int(exitCode.Int64)
			e.ExitCode = &value
		}
		if durationMS.Valid {
			value := durationMS.Int64
			e.DurationMS = &value
		}
		result.EventsChecked++
		if !strings.HasPrefix(storedHash, "v5:") && !strings.HasPrefix(storedHash, eventHashPrefix) && !strings.HasPrefix(storedHash, legacyEventHashPrefix) {
			result.LegacyEvents++
			result.Valid = false
			result.Failures = append(result.Failures, "legacy:"+e.SessionID+":"+strconv.Itoa(e.Sequence))
			// Old 64-character partial hashes and unhashed rows remain readable,
			// but are explicitly legacy and are not claimed as fully verified.
			// Carry the exact stored value because a later v2 event chained to it.
			previous[e.SessionID] = storedHash
			continue
		}
		expectedPrevious := previous[e.SessionID]
		var expectedHash string
		var err error
		if strings.HasPrefix(storedHash, "v5:") {
			expectedHash, err = computeCheckpointEventHash(expectedPrevious, &e, redactedFields, affectedFiles, checkpoint)
		} else if strings.HasPrefix(storedHash, eventHashPrefix) && collectorDetails != "" {
			// Two pre-release implementations used v4. Collector records wrap
			// the v3 digest; affected-file records use a different projection.
			// The stored digest must match the selected historical format.
			expectedHash, err = computeCollectorEventHash(expectedPrevious, &e, redactedFields, collectorDetails)
		} else if strings.HasPrefix(storedHash, eventHashPrefix) {
			expectedHash, err = computeEventHashV3(expectedPrevious, &e, redactedFields, affectedFiles)
		} else {
			expectedHash, err = computeEventHashV2(expectedPrevious, &e, redactedFields)
		}
		if err != nil {
			return nil, fmt.Errorf("hash event %s: %w", e.ID, err)
		}
		collectorFormat := strings.HasPrefix(storedHash, eventHashPrefix) && collectorDetails != ""
		unboundCollector := collectorDetails != "" && !collectorFormat
		unboundAffected := (collectorFormat || strings.HasPrefix(storedHash, legacyEventHashPrefix)) &&
			affectedFiles != "null" && affectedFiles != "" && affectedFiles != "[]"
		if storedPrevious != expectedPrevious || storedHash != expectedHash || unboundCollector || unboundAffected ||
			(checkpoint != "null" && !strings.HasPrefix(storedHash, "v5:")) {
			result.Valid = false
			result.Failures = append(result.Failures, e.SessionID+":"+strconv.Itoa(e.Sequence))
		}
		previous[e.SessionID] = storedHash
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	sessionRows, err := d.db.Query(`SELECT id, agent_name,
		COALESCE(agent_version, ''), COALESCE(model, ''),
		COALESCE(developer_name, ''), COALESCE(developer_email, ''),
		COALESCE(os_user, ''), COALESCE(machine_id, ''),
		COALESCE(working_directory, ''), COALESCE(git_repo_url, ''),
		COALESCE(git_branch, ''), COALESCE(session_hash, '')
		FROM sessions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer sessionRows.Close()
	for sessionRows.Next() {
		result.SessionsChecked++
		var record sessionIntegrityRecord
		var storedHash string
		if err := sessionRows.Scan(
			&record.ID, &record.AgentName, &record.AgentVersion, &record.Model,
			&record.DeveloperName, &record.DeveloperEmail, &record.OSUser,
			&record.MachineID, &record.WorkingDirectory, &record.GitRepoURL,
			&record.GitBranch, &storedHash,
		); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(storedHash, sessionHashPrefix) {
			result.LegacySessions++
			result.Valid = false
			result.Failures = append(result.Failures, "legacy-session:"+record.ID)
			continue
		}
		expectedHash, err := computeSessionHash(record)
		if err != nil {
			return nil, fmt.Errorf("hash session %s: %w", record.ID, err)
		}
		if storedHash != expectedHash {
			result.Valid = false
			result.Failures = append(result.Failures, "session:"+record.ID)
		}
	}
	return result, sessionRows.Err()
}

// SetMeta stores a metadata key-value pair.
func (d *DB) SetMeta(key, value string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.db.Exec(`
		INSERT INTO metadata (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, now,
	)
	return err
}

// Stats holds summary statistics for secuarden status.
type Stats struct {
	TotalSessions int
	TotalEvents   int
	DBSizeBytes   int64
	RecentEvents  []RecentEvent
}

// RecentEvent is a row for the status table.
type RecentEvent struct {
	Timestamp  string
	ActionType string
	Summary    string
}

// GetStats returns summary stats for the status command.
func (d *DB) GetStats(dbPath string) (*Stats, error) {
	s := &Stats{}

	row := d.db.QueryRow("SELECT COUNT(*) FROM sessions")
	_ = row.Scan(&s.TotalSessions)

	row = d.db.QueryRow("SELECT COUNT(*) FROM events")
	_ = row.Scan(&s.TotalEvents)

	if info, err := os.Stat(dbPath); err == nil {
		s.DBSizeBytes = info.Size()
	}

	rows, err := d.db.Query(`
		SELECT timestamp, action_type, COALESCE(file_path, command, tool_name, '') as summary, is_sensitive
		FROM events ORDER BY timestamp DESC LIMIT 5`)
	if err != nil {
		return s, nil
	}
	defer rows.Close()

	for rows.Next() {
		var re RecentEvent
		var summary string
		var isSensitive int
		if err := rows.Scan(&re.Timestamp, &re.ActionType, &summary, &isSensitive); err != nil {
			continue
		}
		if isSensitive == 1 {
			summary = summary + " [SENSITIVE]"
		}
		re.Summary = summary
		s.RecentEvents = append(s.RecentEvents, re)
	}

	return s, nil
}

const SessionEnvelopeSchemaURL = "https://schema.secuarden.ai/upload/1.0/session-envelope.schema.json"
const SessionEnvelopeVersion = "1.0.0"

// SessionEnvelope is the complete, already-redacted SQLite representation sent
// to SaaS. The legacy summary fields remain at top level for older consumers.
type SessionEnvelope struct {
	RepositoryCheckpointStatus map[string]string   `json:"repository_checkpoint_status,omitempty"`
	Schema                     string              `json:"$schema"`
	SchemaVersion              string              `json:"schema_version"`
	SessionID                  string              `json:"session_id"`
	GitRepoURL                 string              `json:"git_repo_url,omitempty"`
	BranchName                 string              `json:"branch_name,omitempty"`
	DeveloperName              string              `json:"developer_name,omitempty"`
	DeveloperEmail             string              `json:"developer_email,omitempty"`
	OSUser                     string              `json:"os_user,omitempty"`
	MachineID                  string              `json:"machine_id,omitempty"`
	AgentName                  string              `json:"agent_name"`
	AgentVersion               string              `json:"agent_version,omitempty"`
	Model                      string              `json:"model,omitempty"`
	WorkingDirectory           string              `json:"working_directory,omitempty"`
	StartedAt                  string              `json:"started_at,omitempty"`
	EndedAt                    string              `json:"ended_at,omitempty"`
	EventCount                 int                 `json:"event_count"`
	FilesEdited                []string            `json:"files_edited,omitempty"`
	PrivacyMode                string              `json:"privacy_mode"`
	Completeness               events.Completeness `json:"completeness"`
	CaptureFailureCount        int                 `json:"capture_failure_count"`
	SessionHash                string              `json:"session_hash,omitempty"`
	Events                     []events.Event      `json:"events"`
	IdempotencyKey             string              `json:"idempotency_key"`
}

// SessionSummary is retained as a source-compatible name for integrations.
type SessionSummary = SessionEnvelope

// PendingSyncSession describes a session whose current event count exceeds its
// last successfully uploaded event count.
type PendingSyncSession struct {
	SessionID            string
	EventCount           int
	LastSyncedEventCount int
}

// ListPendingSyncSessions returns sessions containing locally captured events
// that have not been included in a successful SaaS upload.
func (d *DB) ListPendingSyncSessions(limit int) ([]PendingSyncSession, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.db.Query(`
		SELECT s.id,
		       (SELECT COUNT(*) FROM events e WHERE e.session_id = s.id) AS current_count,
		       COALESCE(ss.last_synced_event_count, 0)
		FROM sessions s
		LEFT JOIN session_sync_state ss ON ss.session_id = s.id
		WHERE (SELECT COUNT(*) FROM events e WHERE e.session_id = s.id)
		      > COALESCE(ss.last_synced_event_count, 0)
		ORDER BY s.started_at, s.id
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending sync sessions: %w", err)
	}
	defer rows.Close()
	var pending []PendingSyncSession
	for rows.Next() {
		var item PendingSyncSession
		if err := rows.Scan(&item.SessionID, &item.EventCount, &item.LastSyncedEventCount); err != nil {
			return nil, fmt.Errorf("scan pending sync session: %w", err)
		}
		pending = append(pending, item)
	}
	return pending, rows.Err()
}

// RecordSyncSuccess checkpoints the exact event count included in a successful
// upload. Events captured afterward make the session pending again.
func (d *DB) RecordSyncSuccess(sessionID string, eventCount int) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.db.Exec(`
		INSERT INTO session_sync_state (
			session_id, last_synced_event_count, last_attempt_at, last_success_at, last_error
		) VALUES (?, ?, ?, ?, NULL)
		ON CONFLICT(session_id) DO UPDATE SET
			last_synced_event_count = excluded.last_synced_event_count,
			last_attempt_at = excluded.last_attempt_at,
			last_success_at = excluded.last_success_at,
			last_error = NULL`,
		sessionID, eventCount, now, now,
	)
	return err
}

// RecordSyncFailure records delivery diagnostics without advancing the
// successful event-count checkpoint.
func (d *DB) RecordSyncFailure(sessionID string, syncErr error) error {
	now := time.Now().UTC().Format(time.RFC3339)
	message := ""
	if syncErr != nil {
		message = syncErr.Error()
	}
	_, err := d.db.Exec(`
		INSERT INTO session_sync_state (
			session_id, last_synced_event_count, last_attempt_at, last_error
		) VALUES (?, 0, ?, ?)
		ON CONFLICT(session_id) DO UPDATE SET
			last_attempt_at = excluded.last_attempt_at,
			last_error = excluded.last_error`,
		sessionID, now, message,
	)
	return err
}

// ReadSessionEnvelope builds the complete upload contract solely from values
// already persisted after local privacy handling.
func (d *DB) ReadSessionEnvelope(sessionID string) (*SessionEnvelope, error) {
	s := &SessionEnvelope{Schema: SessionEnvelopeSchemaURL, SchemaVersion: SessionEnvelopeVersion,
		SessionID: sessionID, Events: []events.Event{}, Completeness: events.Completeness{Reasons: []string{}}}
	var reasonsJSON string

	row := d.db.QueryRow(`
		SELECT
			COALESCE(git_repo_url, ''),
			COALESCE(git_branch, ''),
			COALESCE(developer_name, ''), COALESCE(developer_email, ''), COALESCE(os_user, ''), COALESCE(machine_id, ''),
			COALESCE(agent_name, 'unknown'), COALESCE(agent_version, ''),
			COALESCE(model, ''),
			COALESCE(working_directory, ''),
			COALESCE(started_at, ''),
			COALESCE(ended_at, ''),
			COALESCE(event_count, 0), COALESCE(privacy_mode, 'redacted_content'),
			COALESCE(completeness_state, 'complete'), COALESCE(completeness_reasons, '[]'),
			COALESCE(capture_failure_count, 0), COALESCE(session_hash, '')
		FROM sessions WHERE id = ?`, sessionID)

	if err := row.Scan(
		&s.GitRepoURL, &s.BranchName, &s.DeveloperName, &s.DeveloperEmail, &s.OSUser, &s.MachineID,
		&s.AgentName, &s.AgentVersion, &s.Model, &s.WorkingDirectory,
		&s.StartedAt, &s.EndedAt, &s.EventCount, &s.PrivacyMode,
		&s.Completeness.State, &reasonsJSON, &s.CaptureFailureCount, &s.SessionHash,
	); err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	_ = json.Unmarshal([]byte(reasonsJSON), &s.Completeness.Reasons)

	eventRows, err := d.db.Query(`SELECT id, sequence, timestamp, COALESCE(schema_version,''), COALESCE(captured_at,''), COALESCE(invocation_id,''),
		COALESCE(source,''), COALESCE(source_version,''), COALESCE(agent_name,''), COALESCE(agent_version,''), COALESCE(model,''), COALESCE(provider,''),
		hook_phase, action_type, COALESCE(tool_name,''), COALESCE(result_status,''), COALESCE(outcome,''), COALESCE(permission_status,''), COALESCE(execution_status,''),
		COALESCE(privacy_mode,''), COALESCE(completeness_state,''), COALESCE(completeness_reasons,'[]'), is_sensitive, COALESCE(redacted_fields,'[]'),
		COALESCE(file_path,''), COALESCE(affected_files,'null'), COALESCE(content_hash,''), COALESCE(diff_stats,''), COALESCE(command,''), exit_code, COALESCE(command_output_preview,''),
		COALESCE(mcp_server,''), COALESCE(mcp_tool,''), duration_ms, COALESCE(working_directory,''), COALESCE(git_branch,''), COALESCE(developer_email,''),
		COALESCE(intent_summary,''), COALESCE(raw_event_hash,''), COALESCE(previous_event_hash,''), COALESCE(event_hash,''), COALESCE(repository_checkpoint,'null')
		FROM events WHERE session_id=? ORDER BY sequence`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("read session events: %w", err)
	}
	defer eventRows.Close()
	for eventRows.Next() {
		var e events.Event
		var sensitive int
		var redacted, affectedFiles, reasons, checkpoint string
		if err := eventRows.Scan(&e.ID, &e.Sequence, &e.Timestamp, &e.SchemaVersion, &e.CapturedAt, &e.InvocationID,
			&e.Source, &e.SourceVersion, &e.AgentName, &e.AgentVersion, &e.Model, &e.Provider, &e.HookPhase, &e.ActionType, &e.ToolName,
			&e.ResultStatus, &e.Outcome, &e.PermissionStatus, &e.ExecutionStatus, &e.PrivacyMode, &e.Completeness.State, &reasons, &sensitive, &redacted,
			&e.FilePath, &affectedFiles, &e.ContentHash, &e.DiffStats, &e.Command, &e.ExitCode, &e.CommandOutputPreview, &e.MCPServer, &e.MCPTool, &e.DurationMS,
			&e.WorkingDirectory, &e.GitBranch, &e.DeveloperEmail, &e.IntentSummary, &e.RawEventHash, &e.PreviousEventHash, &e.EventHash, &checkpoint); err != nil {
			return nil, err
		}
		if e.SchemaVersion == "" {
			e.Schema = "https://schema.secuarden.ai/v1/event.schema.json"
			e.SchemaVersion = "1.0.0"
		} else {
			e.Schema = events.SchemaURL
		}
		e.SessionID = sessionID
		e.IsSensitive = sensitive != 0
		_ = json.Unmarshal([]byte(redacted), &e.RedactedFields)
		_ = json.Unmarshal([]byte(affectedFiles), &e.AffectedFiles)
		_ = json.Unmarshal([]byte(reasons), &e.Completeness.Reasons)
		if err := json.Unmarshal([]byte(checkpoint), &e.RepositoryCheckpoint); err != nil {
			return nil, fmt.Errorf("decode repository checkpoint: %w", err)
		}
		if e.RedactedFields == nil {
			e.RedactedFields = []string{}
		}
		if e.Completeness.Reasons == nil {
			e.Completeness.Reasons = []string{}
		}
		s.Events = append(s.Events, e)
	}
	if err := eventRows.Err(); err != nil {
		return nil, err
	}
	s.RepositoryCheckpointStatus = map[string]string{"baseline": "absent", "end": "absent"}
	for _, e := range s.Events {
		if c := e.RepositoryCheckpoint; c != nil {
			if e.HookPhase == events.HookPhaseSessionStart && s.RepositoryCheckpointStatus["baseline"] == "absent" {
				s.RepositoryCheckpointStatus["baseline"] = c.Status
			}
			if e.HookPhase == events.HookPhaseSessionEnd {
				s.RepositoryCheckpointStatus["end"] = c.Status
			}
		}
	}
	edited := map[string]bool{}
	for _, e := range s.Events {
		if e.HookPhase != events.HookPhasePost || e.Outcome != events.ResultSuccess || e.ExecutionStatus != "completed" {
			continue
		}
		if len(e.AffectedFiles) == 0 {
			if e.ActionType == events.ActionFileWrite && !e.IsSensitive && e.FilePath != "" {
				edited[e.FilePath] = true
			}
			continue
		}
		for _, file := range e.AffectedFiles {
			if !file.IsSensitive && file.Path != "" {
				edited[file.Path] = true
			}
		}
	}
	for path := range edited {
		s.FilesEdited = append(s.FilesEdited, path)
	}
	sort.Strings(s.FilesEdited)
	canonical := struct {
		SchemaVersion, SessionID, SessionHash string
		EventCount                            int
		Events                                []events.Event
	}{s.SchemaVersion, s.SessionID, s.SessionHash, len(s.Events), s.Events}
	b, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(b)
	s.IdempotencyKey = fmt.Sprintf("%x", digest[:])
	s.EventCount = len(s.Events)
	return s, nil
}

// ReadSessionSummary now returns the complete envelope while preserving the old API name.
func (d *DB) ReadSessionSummary(sessionID string) (*SessionSummary, error) {
	return d.ReadSessionEnvelope(sessionID)
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// v5 binds the exact checkpoint JSON into the existing complete event hash.
func computeCheckpointEventHash(previous string, e *events.Event, redacted, affected, checkpoint string) (string, error) {
	base, err := computeEventHashV3(previous, e, redacted, affected)
	if err != nil || checkpoint == "null" {
		return base, err
	}
	return hashCanonicalJSON("v5:", struct {
		Event      string `json:"event"`
		Checkpoint string `json:"checkpoint"`
	}{base, checkpoint})
}

// computeCollectorEventHash reproduces the historical public collector's v4
// format exactly, including the raw JSON string. It is verification-only: new
// events continue to use the affected-file/checkpoint formats. Do not normalize
// details or rewrite stored hashes during migration.
func computeCollectorEventHash(previous string, e *events.Event, redactedFields, details string) (string, error) {
	base, err := computeEventHashV2(previous, e, redactedFields)
	if err != nil {
		return "", err
	}
	return hashCanonicalJSON("v4:", struct {
		FormatVersion    int    `json:"format_version"`
		EvidenceHash     string `json:"evidence_hash"`
		CollectorDetails string `json:"collector_details"`
	}{4, base, details})
}
