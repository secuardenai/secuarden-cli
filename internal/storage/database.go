package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	// busy_timeout makes writers wait up to 5 s instead of returning SQLITE_BUSY.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
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

	return &DB{db: db}, nil
}

func isDuplicateColumnError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "duplicate column")
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.db.Close()
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

// NextSequence returns the next sequence number for a session.
func (d *DB) NextSequence(sessionID string) (int, error) {
	var seq int
	row := d.db.QueryRow(
		"SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE session_id = ?",
		sessionID,
	)
	if err := row.Scan(&seq); err != nil {
		return 1, err
	}
	return seq, nil
}

// WriteEvent inserts an event into the database.
func (d *DB) WriteEvent(e *events.Event) error {
	redactedJSON, err := json.Marshal(e.RedactedFields)
	if err != nil {
		redactedJSON = []byte("[]")
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

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin event write: %w", err)
	}
	defer tx.Rollback()
	var previousHash string
	_ = tx.QueryRow(`SELECT COALESCE(event_hash, '') FROM events
		WHERE session_id = ? ORDER BY sequence DESC LIMIT 1`, e.SessionID).Scan(&previousHash)
	eventHash, err := computeEventHashV2(previousHash, e, string(redactedJSON))
	if err != nil {
		return fmt.Errorf("hash event: %w", err)
	}
	_, err = tx.Exec(`
		INSERT INTO events (
			id, session_id, sequence, timestamp,
			source, source_version,
			agent_name, hook_phase, action_type, tool_name,
			result_status,
			is_sensitive, redacted_fields,
			file_path, content_hash, diff_stats,
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
			?,?,?,
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
		nullStr(e.FilePath), nullStr(e.ContentHash), nullStr(e.DiffStats),
		nullStr(e.Command), exitCode, nullStr(e.CommandOutputPreview),
		nullStr(e.MCPServer), nullStr(e.MCPTool),
		durationMS,
		nullStr(e.WorkingDirectory), nullStr(e.GitBranch),
		nullStr(e.DeveloperEmail), nullStr(e.IntentSummary), nullStr(e.RawEventHash),
		nullStr(previousHash), eventHash,
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}

	// Keep event_count in sessions up to date
	_, _ = tx.Exec(
		"UPDATE sessions SET event_count = event_count + 1 WHERE id = ?",
		e.SessionID,
	)
	return tx.Commit()
}

const (
	eventHashPrefix   = "v2:"
	sessionHashPrefix = "s1:"
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
	Source               string `json:"source"`
	SourceVersion        string `json:"source_version"`
	AgentName            string `json:"agent_name"`
	HookPhase            string `json:"hook_phase"`
	ActionType           string `json:"action_type"`
	ToolName             string `json:"tool_name"`
	ResultStatus         string `json:"result_status"`
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
	return hashCanonicalJSON(eventHashPrefix, eventIntegrityRecordV2{
		FormatVersion: 2, PreviousEventHash: previous,
		ID: e.ID, SessionID: e.SessionID, Sequence: e.Sequence, Timestamp: e.Timestamp,
		Source: e.Source, SourceVersion: e.SourceVersion, AgentName: e.AgentName,
		HookPhase: e.HookPhase, ActionType: e.ActionType, ToolName: e.ToolName,
		ResultStatus: e.ResultStatus, IsSensitive: e.IsSensitive,
		RedactedFields: redactedFields, FilePath: e.FilePath, ContentHash: e.ContentHash,
		DiffStats: e.DiffStats, Command: e.Command, ExitCode: e.ExitCode,
		CommandOutputPreview: e.CommandOutputPreview, MCPServer: e.MCPServer,
		MCPTool: e.MCPTool, DurationMS: e.DurationMS, WorkingDirectory: e.WorkingDirectory,
		GitBranch: e.GitBranch, DeveloperEmail: e.DeveloperEmail,
		IntentSummary: e.IntentSummary, RawEventHash: e.RawEventHash,
	})
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
		COALESCE(e.file_path, ''), COALESCE(e.content_hash, ''),
		e.agent_name, COALESCE(s.model, ''), COALESCE(s.developer_email, ''),
		COALESCE(s.git_repo_url, ''), COALESCE(s.git_branch, ''),
		e.is_sensitive, COALESCE(e.event_hash, '')
		FROM events e JOIN sessions s ON s.id=e.session_id
		WHERE e.action_type='file_write' AND e.timestamp >= ?
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
	rows, err := d.db.Query(`SELECT id, session_id, sequence, timestamp,
		source, COALESCE(source_version, ''), agent_name, hook_phase, action_type,
		COALESCE(tool_name, ''), COALESCE(result_status, ''), is_sensitive,
		COALESCE(redacted_fields, 'null'), COALESCE(file_path, ''),
		COALESCE(content_hash, ''), COALESCE(diff_stats, ''),
		COALESCE(command, ''), exit_code, COALESCE(command_output_preview, ''),
		COALESCE(mcp_server, ''), COALESCE(mcp_tool, ''), duration_ms,
		COALESCE(working_directory, ''), COALESCE(git_branch, ''),
		COALESCE(developer_email, ''), COALESCE(intent_summary, ''),
		COALESCE(raw_event_hash, ''),
		COALESCE(previous_event_hash, ''), COALESCE(event_hash, '')
		FROM events ORDER BY session_id, sequence, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := &IntegrityResult{Valid: true}
	previous := map[string]string{}
	for rows.Next() {
		var e events.Event
		var redactedFields, storedPrevious, storedHash string
		var sensitive int
		var exitCode, durationMS sql.NullInt64
		if err := rows.Scan(
			&e.ID, &e.SessionID, &e.Sequence, &e.Timestamp, &e.Source,
			&e.SourceVersion, &e.AgentName, &e.HookPhase, &e.ActionType,
			&e.ToolName, &e.ResultStatus, &sensitive, &redactedFields,
			&e.FilePath, &e.ContentHash, &e.DiffStats, &e.Command, &exitCode,
			&e.CommandOutputPreview, &e.MCPServer, &e.MCPTool, &durationMS,
			&e.WorkingDirectory, &e.GitBranch, &e.DeveloperEmail,
			&e.IntentSummary, &e.RawEventHash, &storedPrevious, &storedHash,
		); err != nil {
			return nil, err
		}
		e.IsSensitive = sensitive == 1
		if exitCode.Valid {
			value := int(exitCode.Int64)
			e.ExitCode = &value
		}
		if durationMS.Valid {
			value := durationMS.Int64
			e.DurationMS = &value
		}
		result.EventsChecked++
		if !strings.HasPrefix(storedHash, eventHashPrefix) {
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
		expectedHash, err := computeEventHashV2(expectedPrevious, &e, redactedFields)
		if err != nil {
			return nil, fmt.Errorf("hash event %s: %w", e.ID, err)
		}
		if storedPrevious != expectedPrevious || storedHash != expectedHash {
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

// SessionSummary is the payload sent to the SaaS on session-end sync.
type SessionSummary struct {
	SessionID        string   `json:"session_id"`
	GitRepoURL       string   `json:"git_repo_url,omitempty"`
	BranchName       string   `json:"branch_name,omitempty"`
	DeveloperEmail   string   `json:"developer_email,omitempty"`
	Model            string   `json:"model,omitempty"`
	WorkingDirectory string   `json:"working_directory,omitempty"`
	StartedAt        string   `json:"started_at,omitempty"`
	EndedAt          string   `json:"ended_at,omitempty"`
	EventCount       int      `json:"event_count"`
	FilesEdited      []string `json:"files_edited,omitempty"`
}

// ReadSessionSummary reads the session row and collects unique edited file paths
// from the events table. Used to build the payload for SaaS sync.
func (d *DB) ReadSessionSummary(sessionID string) (*SessionSummary, error) {
	s := &SessionSummary{SessionID: sessionID}

	row := d.db.QueryRow(`
		SELECT
			COALESCE(git_repo_url, ''),
			COALESCE(git_branch, ''),
			COALESCE(developer_email, ''),
			COALESCE(model, ''),
			COALESCE(working_directory, ''),
			COALESCE(started_at, ''),
			COALESCE(ended_at, ''),
			COALESCE(event_count, 0)
		FROM sessions WHERE id = ?`, sessionID)

	if err := row.Scan(
		&s.GitRepoURL, &s.BranchName, &s.DeveloperEmail,
		&s.Model, &s.WorkingDirectory,
		&s.StartedAt, &s.EndedAt, &s.EventCount,
	); err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}

	rows, err := d.db.Query(`
		SELECT DISTINCT file_path FROM events
		WHERE session_id = ?
		  AND action_type = 'file_write'
		  AND file_path IS NOT NULL
		  AND is_sensitive = 0
		ORDER BY file_path`, sessionID)
	if err != nil {
		return s, nil // non-fatal: return summary without files
	}
	defer rows.Close()

	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err == nil && fp != "" {
			s.FilesEdited = append(s.FilesEdited, fp)
		}
	}
	return s, nil
}

func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
