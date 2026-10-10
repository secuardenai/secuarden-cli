package changeledger

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
)

const observationSchema = `
CREATE TABLE IF NOT EXISTS codex_observations (
 id TEXT PRIMARY KEY, logical_id TEXT NOT NULL, session_id TEXT NOT NULL,
 repository TEXT NOT NULL, record_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS codex_observations_session ON codex_observations(session_id);
CREATE INDEX IF NOT EXISTS codex_observations_logical ON codex_observations(logical_id);
CREATE TABLE IF NOT EXISTS codex_deliveries (
 id TEXT PRIMARY KEY, observation_id TEXT NOT NULL, received_at TEXT NOT NULL,
 raw_hash TEXT NOT NULL, disposition TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observation_gaps (
 id TEXT PRIMARY KEY, code TEXT NOT NULL, session_id TEXT NOT NULL,
 observed_at TEXT NOT NULL, record_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observation_runs (
 id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, inbox TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ledger_checkpoints (
 id TEXT PRIMARY KEY, session_id TEXT NOT NULL, repository TEXT NOT NULL, record_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS change_observation_scopes (
 change_digest TEXT NOT NULL, session_id TEXT NOT NULL, since TEXT NOT NULL, until TEXT NOT NULL,
 PRIMARY KEY(change_digest, session_id));
CREATE TABLE IF NOT EXISTS change_observation_links (
 change_digest TEXT NOT NULL, observation_id TEXT NOT NULL, record_json TEXT NOT NULL,
 PRIMARY KEY(change_digest, observation_id));
`

type CoverageGap struct {
	Version       string    `json:"version"`
	Code          string    `json:"code"`
	SessionID     string    `json:"session_id,omitempty"`
	ObservationID string    `json:"observation_id,omitempty"`
	Source        string    `json:"source"`
	SourceVersion string    `json:"source_version"`
	ObservedAt    time.Time `json:"observed_at"`
	Detail        string    `json:"detail,omitempty"`
}

func (s *Store) RecordGap(g CoverageGap) error {
	if g.Version == "" {
		g.Version = ContractVersion
	}
	if g.SourceVersion == "" {
		g.SourceVersion = observationcapture.Version
	}
	if g.ObservedAt.IsZero() {
		g.ObservedAt = time.Now().UTC()
	}
	data, err := json.Marshal(g)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR IGNORE INTO observation_gaps VALUES(?,?,?,?,?)`,
		observationcapture.Hash(data), g.Code, g.SessionID, g.ObservedAt.Format(time.RFC3339Nano), string(data))
	return err
}

func (s *Store) saveDelivery(e observationcapture.Envelope, o *observationcapture.Observation, rejected string) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM codex_deliveries WHERE id=?`, e.ID).Scan(&exists); err != nil {
		return "", err
	}
	if exists > 0 {
		return "replayed", nil
	}
	disposition, observationID := "accepted", ""
	if o != nil {
		observationID = o.ID
		data, err := json.Marshal(o)
		if err != nil {
			return "", err
		}
		if err := tx.QueryRow(`SELECT COUNT(*) FROM codex_observations WHERE id=?`, o.ID).Scan(&exists); err != nil {
			return "", err
		}
		if exists > 0 {
			disposition = "duplicate"
			var previous string
			if err := tx.QueryRow(`SELECT record_json FROM codex_observations WHERE id=?`, o.ID).Scan(&previous); err != nil {
				return "", err
			}
			var old observationcapture.Observation
			if err := json.Unmarshal([]byte(previous), &old); err != nil {
				return "", err
			}
			// File order and batch boundaries must not choose receipt time.
			// Preserve the first processing-time repository evidence.
			if o.ReceivedAt.Before(old.ReceivedAt) {
				old.ReceivedAt = o.ReceivedAt
				if old.TimeBasis == "receipt" {
					old.OccurredAt = o.ReceivedAt
				}
				data, err := json.Marshal(old)
				if err != nil {
					return "", err
				}
				if _, err := tx.Exec(`UPDATE codex_observations SET record_json=? WHERE id=?`, string(data), o.ID); err != nil {
					return "", err
				}
			}
		} else {
			if err := tx.QueryRow(`SELECT COUNT(*) FROM codex_observations WHERE logical_id=?`, o.LogicalID).Scan(&exists); err != nil {
				return "", err
			}
			if exists > 0 {
				disposition = "conflict"
			}
			if _, err := tx.Exec(`INSERT INTO codex_observations VALUES(?,?,?,?,?)`, o.ID, o.LogicalID, o.SessionID, o.Repository, string(data)); err != nil {
				return "", err
			}
		}
	} else {
		disposition = "rejected"
		g := CoverageGap{Version: ContractVersion, Code: rejected, Source: "codex-inbox", SourceVersion: observationcapture.Version, ObservedAt: e.ReceivedAt, Detail: "Delivery " + e.ID + " could not be normalized; no observation was invented."}
		data, err := json.Marshal(g)
		if err != nil {
			return "", err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO observation_gaps VALUES(?,?,?,?,?)`, e.ID, g.Code, "", e.ReceivedAt.Format(time.RFC3339Nano), string(data)); err != nil {
			return "", err
		}
	}
	if _, err := tx.Exec(`INSERT INTO codex_deliveries VALUES(?,?,?,?,?)`, e.ID, observationID, e.ReceivedAt.Format(time.RFC3339Nano), e.Hash, disposition); err != nil {
		return "", err
	}
	return disposition, tx.Commit()
}

func (s *Store) Observations(session string) ([]observationcapture.Observation, error) {
	query, args := `SELECT record_json FROM codex_observations`, []interface{}{}
	if session != "" {
		query += ` WHERE session_id=?`
		args = append(args, session)
	}
	query += ` ORDER BY id`
	rows, err := s.reader().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []observationcapture.Observation{}
	for rows.Next() {
		var data string
		var o observationcapture.Observation
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &o); err != nil {
			return nil, err
		}
		result = append(result, o)
	}
	return result, rows.Err()
}

func (s *Store) storedGaps() ([]CoverageGap, error) {
	rows, err := s.reader().Query(`SELECT record_json FROM observation_gaps ORDER BY observed_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []CoverageGap{}
	for rows.Next() {
		var data string
		var g CoverageGap
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &g); err != nil {
			return nil, err
		}
		result = append(result, g)
	}
	return result, rows.Err()
}

func (s *Store) deliveryCounts(id string) (duplicates, conflicts int, err error) {
	err = s.reader().QueryRow(`SELECT COALESCE(SUM(disposition='duplicate'),0), COALESCE(SUM(disposition='conflict'),0) FROM codex_deliveries WHERE observation_id=?`, id).Scan(&duplicates, &conflicts)
	return
}

func (s *Store) beginObservationRun(id, dir string) error {
	var unfinished int
	if err := s.reader().QueryRow(`SELECT COUNT(*) FROM observation_runs WHERE inbox=? AND finished_at IS NULL`, dir).Scan(&unfinished); err != nil {
		return err
	}
	if unfinished > 0 {
		if err := s.RecordGap(CoverageGap{Code: "process_restart", Source: "observation-processor", Detail: "An earlier processor did not finish; durable inputs are being replayed."}); err != nil {
			return err
		}
		if _, err := s.db.Exec(`UPDATE observation_runs SET finished_at='interrupted' WHERE inbox=? AND finished_at IS NULL`, dir); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`INSERT INTO observation_runs VALUES(?,?,NULL,?)`, id, time.Now().UTC().Format(time.RFC3339Nano), dir)
	return err
}

func (s *Store) finishObservationRun(id string) error {
	result, err := s.db.Exec(`UPDATE observation_runs SET finished_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return fmt.Errorf("unknown processor run")
	}
	return nil
}
