package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
)

// LiveRecord deliberately excludes payloads, prompts and command text.
type LiveRecord struct {
	CapturedAt string
	ID         string
	Session    string
	Agent      string
	Version    string
	Invocation string
	Phase      string
	Tool       string
	Directory  string
}

func (d *DB) LiveWatermark() (int64, error) {
	var n int64
	err := d.db.QueryRow(`SELECT COALESCE(MAX(rowid),0) FROM events`).Scan(&n)
	return n, err
}

func (d *DB) LiveEvidence(after int64, session, agent string) ([]LiveRecord, bool, int, error) {
	var old, failures int
	if err := d.db.QueryRow(`SELECT count(*) FROM events WHERE session_id=? AND rowid<=?`, session, after).Scan(&old); err != nil {
		return nil, false, 0, err
	}
	if err := d.db.QueryRow(`SELECT count(*) FROM capture_failures WHERE session_id=?`, session).Scan(&failures); err != nil {
		return nil, false, 0, err
	}
	rows, err := d.db.Query(`SELECT COALESCE(captured_at,''), id, session_id, agent_name, COALESCE(agent_version,''), COALESCE(invocation_id,''), hook_phase, COALESCE(tool_name,''), COALESCE(working_directory,'') FROM events WHERE rowid>? AND session_id=? AND agent_name=? ORDER BY rowid`, after, session, agent)
	if err != nil {
		return nil, false, 0, err
	}
	defer rows.Close()
	var records []LiveRecord
	for rows.Next() {
		var r LiveRecord
		if err := rows.Scan(&r.CapturedAt, &r.ID, &r.Session, &r.Agent, &r.Version, &r.Invocation, &r.Phase, &r.Tool, &r.Directory); err != nil {
			return nil, false, 0, err
		}
		records = append(records, r)
	}
	return records, old > 0, failures, rows.Err()
}

func (d *DB) ReadLiveState(key string, value interface{}) (bool, error) {
	var raw string
	err := d.db.QueryRow(`SELECT value FROM metadata WHERE key=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), value)
}
func (d *DB) WriteLiveState(key string, value interface{}) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return d.SetMeta(key, string(raw))
}
