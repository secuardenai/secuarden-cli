package storage

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenWaitsForStartupLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked.db")
	owner, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	owner.SetMaxOpenConns(1)
	if _, err := owner.Exec("CREATE TABLE startup_probe (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec("BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	defer owner.Exec("ROLLBACK")
	if _, err := owner.Exec("INSERT INTO startup_probe VALUES ('preserved')"); err != nil {
		t.Fatal(err)
	}

	type result struct {
		db  *DB
		err error
	}
	finished := make(chan result, 1)
	go func() { db, err := Open(path); finished <- result{db, err} }()
	// A competing hook must wait for a short-lived lock, not lose its event
	// by failing during the journal-mode pragma before busy_timeout is set.
	select {
	case r := <-finished:
		if r.db != nil {
			r.db.Close()
		}
		t.Fatalf("Open returned while startup lock was held: %v", r.err)
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := owner.Exec("COMMIT"); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-finished:
		if r.err != nil {
			t.Fatalf("Open after lock release: %v", r.err)
		}
		defer r.db.Close()
		var value, mode string
		if err := r.db.db.QueryRow("SELECT value FROM startup_probe").Scan(&value); err != nil {
			t.Fatal(err)
		}
		if value != "preserved" {
			t.Fatalf("existing data changed: %q", value)
		}
		if err := r.db.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
			t.Fatal(err)
		}
		if mode != "wal" {
			t.Fatalf("journal mode = %q", mode)
		}
		if err := r.db.EnsureSession("after-lock", "claude-code", "/test"); err != nil {
			t.Fatal(err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("Open did not finish after lock release")
	}
}
