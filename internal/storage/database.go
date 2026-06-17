package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
	"github.com/secuardenai/secuarden-cli/internal/events"
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

	return &DB{db: db}, nil
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// EnsureSession creates a session row if it doesn't exist. Returns the session ID.
func (d *DB) EnsureSession(sessionID, agentName, workingDir string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := d.db.Exec(`
		INSERT OR IGNORE INTO sessions (id, agent_name, working_directory, started_at)
		VALUES (?, ?, ?, ?)`,
		sessionID, agentName, workingDir, now,
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

// UpdateSession sets optional session fields (identity, git, model).
func (d *DB) UpdateSession(sessionID string, fields map[string]interface{}) error {
	for key, val := range fields {
		if _, err := d.db.Exec(
			fmt.Sprintf("UPDATE sessions SET %s = ? WHERE id = ?", key),
			val, sessionID,
		); err != nil {
			return err
		}
	}
	return nil
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

	_, err = d.db.Exec(`
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
			developer_email, intent_summary, raw_event_hash
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
			?,?,?
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
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}

	// Keep event_count in sessions up to date
	_, _ = d.db.Exec(
		"UPDATE sessions SET event_count = event_count + 1 WHERE id = ?",
		e.SessionID,
	)
	return nil
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
