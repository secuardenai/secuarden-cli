package attestation

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

func DefaultPath() (string, error) {
	h, e := os.UserHomeDir()
	return filepath.Join(h, ".secuarden", "attestation.db"), e
}
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL", `CREATE TABLE IF NOT EXISTS configuration_attestation (sequence INTEGER PRIMARY KEY, body TEXT NOT NULL, hash TEXT NOT NULL)`} {
		if _, err = db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &Store{db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h)
}
func load(conn *sql.Conn) ([]Event, error) {
	rows, err := conn.QueryContext(context.Background(), "SELECT sequence,body,hash FROM configuration_attestation ORDER BY sequence")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []Event{}
	prev := ""
	for rows.Next() {
		var seq int
		var body, hash string
		if err := rows.Scan(&seq, &body, &hash); err != nil {
			return nil, err
		}
		var e Event
		if err := json.Unmarshal([]byte(body), &e); err != nil {
			return nil, fmt.Errorf("invalid attestation record %d", seq)
		}
		if seq != len(events)+1 || e.Sequence != seq || e.PreviousHash != prev || e.Hash != "" || digest(e) != hash {
			return nil, fmt.Errorf("attestation checksum failed at record %d", seq)
		}
		e.Hash = hash
		prev = hash
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) Read(now time.Time) (Report, error) {
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return Report{}, err
	}
	defer conn.Close()
	events, err := load(conn)
	if err != nil {
		return Report{}, err
	}
	return summarize(events, now), nil
}
