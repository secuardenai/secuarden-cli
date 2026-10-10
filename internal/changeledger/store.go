package changeledger

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db     *sql.DB
	path   string
	readTx *sql.Tx
}

func DefaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".secuarden", "ledger.db"), nil
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
	for _, statement := range []string{
		"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000",
		`CREATE TABLE IF NOT EXISTS changes (
		 digest TEXT PRIMARY KEY, version TEXT NOT NULL, repository TEXT NOT NULL,
		 base_commit TEXT NOT NULL, head_commit TEXT NOT NULL,
		 record_json TEXT NOT NULL, stored_at TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS changes_revision ON changes(repository, base_commit, head_commit)`,
		observationSchema,
		signedSchema,
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, path: path}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Put(c *Change) (Receipt, error) {
	if c == nil || c.Digest == "" || c.Status != "complete" {
		return Receipt{}, fmt.Errorf("only complete changes can be stored")
	}
	copy := *c
	if err := copy.setDigest(); err != nil {
		return Receipt{}, err
	}
	if copy.Digest != c.Digest {
		return Receipt{}, fmt.Errorf("change digest mismatch")
	}
	data, err := json.Marshal(c)
	if err != nil {
		return Receipt{}, err
	}
	storedAt := time.Now().UTC().Format(time.RFC3339Nano)
	var actual string
	err = s.db.QueryRow(`INSERT INTO changes(digest,version,repository,base_commit,head_commit,record_json,stored_at)
		VALUES(?,?,?,?,?,?,?) ON CONFLICT(digest) DO UPDATE SET
		version=excluded.version, repository=excluded.repository,
		base_commit=excluded.base_commit, head_commit=excluded.head_commit,
		record_json=excluded.record_json, stored_at=excluded.stored_at
		RETURNING stored_at`, c.Digest, c.Version, c.Repository, c.BaseCommit, c.HeadCommit, string(data), storedAt).Scan(&actual)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{Version: ContractVersion, ChangeDigest: c.Digest, StoredAt: actual, Database: s.path}, nil
}

func (s *Store) Get(digest string) (*Change, Receipt, error) {
	if !strings.HasPrefix(digest, "sha256:") {
		return nil, Receipt{}, fmt.Errorf("invalid change digest")
	}
	var data, storedAt string
	if err := s.reader().QueryRow(`SELECT record_json,stored_at FROM changes WHERE digest=?`, digest).Scan(&data, &storedAt); err != nil {
		return nil, Receipt{}, err
	}
	var c Change
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		return nil, Receipt{}, err
	}
	if c.Digest != digest {
		return nil, Receipt{}, fmt.Errorf("stored change digest mismatch")
	}
	copy := c
	if err := copy.setDigest(); err != nil {
		return nil, Receipt{}, err
	}
	if copy.Digest != digest {
		return nil, Receipt{}, fmt.Errorf("stored change content mismatch")
	}
	return &c, Receipt{Version: ContractVersion, ChangeDigest: digest, StoredAt: storedAt, Database: s.path}, nil
}
