package storage

import (
	"database/sql"
)

// EditRevision is the redacted before/after of one agent edit.
// It is stored beside the event hash chain and is not part of the event hash.
type EditRevision struct {
	EventID   string
	SessionID string
	Path      string
	Before    string
	After     string
	Truncated bool
}

// PostureFinding is a detector result for one edit.
type PostureFinding struct {
	ID            string
	EventID       string
	SessionID     string
	Kind          string
	Path          string
	PromptExcerpt string
	Explanation   string
}

// ChainEdit is a captured file write joined to its revision.
type ChainEdit struct {
	EventID          string
	SessionID        string
	Path             string
	Intent           string
	WorkingDirectory string
	Before           string
	After            string
	Findings         []PostureFinding
}

func (d *DB) LatestIntent(sessionID string) (string, error) {
	var intent string
	err := d.db.QueryRow(`SELECT COALESCE(intent_summary, '') FROM events
		WHERE session_id = ? AND action_type = 'developer_intent' AND TRIM(COALESCE(intent_summary, '')) != ''
		ORDER BY sequence DESC LIMIT 1`, sessionID).Scan(&intent)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return intent, err
}

func (d *DB) SaveEditRevision(revision EditRevision) error {
	truncated := 0
	if revision.Truncated {
		truncated = 1
	}
	_, err := d.db.Exec(`INSERT INTO edit_revisions (event_id, session_id, path, before_text, after_text, truncated)
		VALUES (?, ?, ?, ?, ?, ?)`, revision.EventID, revision.SessionID, revision.Path, revision.Before, revision.After, truncated)
	return err
}

func (d *DB) SaveFindings(findings []PostureFinding) error {
	for _, finding := range findings {
		if _, err := d.db.Exec(`INSERT INTO posture_findings
			(id, event_id, session_id, kind, path, prompt_excerpt, explanation)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, finding.ID, finding.EventID, finding.SessionID, finding.Kind, finding.Path, finding.PromptExcerpt, finding.Explanation); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) EditRevision(eventID string) (EditRevision, error) {
	var revision EditRevision
	var truncated int
	err := d.db.QueryRow(`SELECT event_id, session_id, path, before_text, after_text, truncated FROM edit_revisions WHERE event_id = ?`, eventID).
		Scan(&revision.EventID, &revision.SessionID, &revision.Path, &revision.Before, &revision.After, &truncated)
	revision.Truncated = truncated == 1
	return revision, err
}

func (d *DB) FindingsForEvent(eventID string) ([]PostureFinding, error) {
	rows, err := d.db.Query(`SELECT id, event_id, session_id, kind, path, prompt_excerpt, explanation
		FROM posture_findings WHERE event_id = ? ORDER BY kind, id`, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []PostureFinding
	for rows.Next() {
		var finding PostureFinding
		if err := rows.Scan(&finding.ID, &finding.EventID, &finding.SessionID, &finding.Kind, &finding.Path, &finding.PromptExcerpt, &finding.Explanation); err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

// ListChainEdits returns captured file writes and any stored revision or findings.
func (d *DB) ListChainEdits() ([]ChainEdit, error) {
	rows, err := d.db.Query(`SELECT e.id, e.session_id, COALESCE(e.file_path, ''), COALESCE(e.intent_summary, ''),
		COALESCE(e.working_directory, ''), COALESCE(r.before_text, ''), COALESCE(r.after_text, ''), COALESCE(r.path, '')
		FROM events e
		LEFT JOIN edit_revisions r ON r.event_id = e.id
		WHERE e.action_type = 'file_write' AND e.hook_phase = 'post'
		ORDER BY e.session_id, e.sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var edits []ChainEdit
	for rows.Next() {
		var edit ChainEdit
		var revisionPath string
		if err := rows.Scan(&edit.EventID, &edit.SessionID, &edit.Path, &edit.Intent, &edit.WorkingDirectory, &edit.Before, &edit.After, &revisionPath); err != nil {
			return nil, err
		}
		if edit.Path == "" {
			edit.Path = revisionPath
		}
		edits = append(edits, edit)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range edits {
		findings, err := d.FindingsForEvent(edits[i].EventID)
		if err != nil {
			return nil, err
		}
		edits[i].Findings = findings
	}
	return edits, nil
}
