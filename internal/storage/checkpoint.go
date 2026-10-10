package storage

import (
	"database/sql"
	"encoding/json"

	"github.com/secuardenai/secuarden-cli/internal/events"
)

// CheckpointContext returns the original start and most recent event. Reading
// the immediate predecessor makes overlapping invocations conservative.
func (d *DB) CheckpointContext(sessionID string) (baseline, previous *events.Event, err error) {
	read := func(query string) (*events.Event, error) {
		var e events.Event
		var checkpoint string
		err := d.db.QueryRow(query, sessionID).Scan(&e.Sequence, &e.HookPhase, &e.InvocationID, &e.ToolName, &checkpoint)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(checkpoint), &e.RepositoryCheckpoint); err != nil {
			return nil, err
		}
		return &e, nil
	}
	const fields = `SELECT sequence,hook_phase,COALESCE(invocation_id,''),COALESCE(tool_name,''),COALESCE(repository_checkpoint,'null') FROM events WHERE session_id=? `
	baseline, err = read(fields + `AND hook_phase='session_start' ORDER BY sequence LIMIT 1`)
	if err != nil {
		return
	}
	previous, err = read(fields + `ORDER BY sequence DESC LIMIT 1`)
	return
}
