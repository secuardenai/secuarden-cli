package changeledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
	"github.com/secuardenai/secuarden-cli/internal/repository"
)

var errCheckpointStorage = errors.New("store observation checkpoint")

// ObservationCheckpoint is a current Git observation made outside the hook.
// It is never backdated to the time a delayed delivery claims to have occurred.
type ObservationCheckpoint struct {
	Version       string    `json:"version"`
	ID            string    `json:"id"`
	SessionID     string    `json:"session_id"`
	Kind          string    `json:"kind"`
	Repository    string    `json:"repository"`
	Root          string    `json:"root"`
	Commit        string    `json:"commit"`
	Tree          string    `json:"tree"`
	ObservedAt    time.Time `json:"observed_at"`
	Source        string    `json:"source"`
	SourceVersion string    `json:"source_version"`
}

func (s *Store) Checkpoint(path, session, kind string) (*ObservationCheckpoint, error) {
	if session == "" || (kind != "start" && kind != "end" && kind != "processing") {
		return nil, fmt.Errorf("session and start/end/processing checkpoint kind are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	git := func(args ...string) (string, error) {
		command := exec.CommandContext(ctx, "git", append([]string{"-C", path}, args...)...)
		command.Env = gitEnvironment()
		out, err := command.Output()
		return strings.TrimSuffix(string(out), "\n"), err
	}
	root, err := git("rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	path = root
	commit, err := git("rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return nil, err
	}
	tree, err := git("rev-parse", "--verify", commit+"^{tree}")
	if err != nil {
		return nil, err
	}
	identity := "local:" + filepath.ToSlash(root)
	if remote, err := git("remote", "get-url", "origin"); err == nil {
		if canonical, _, err := repository.NormalizeRemote(remote); err == nil {
			identity = canonical
		}
	}
	version, err := git("--version")
	if err != nil {
		version = "unknown"
	}
	c := &ObservationCheckpoint{Version: ContractVersion, SessionID: session, Kind: kind, Repository: identity,
		Root: root, Commit: commit, Tree: tree, ObservedAt: time.Now().UTC(), Source: "git rev-parse", SourceVersion: version}
	if err := s.saveCheckpoint(c); err != nil {
		return nil, fmt.Errorf("%w: %w", errCheckpointStorage, err)
	}
	return c, nil
}

func (s *Store) saveCheckpoint(c *ObservationCheckpoint) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	c.ID = observationcapture.Hash(b)
	b, err = json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR IGNORE INTO ledger_checkpoints VALUES(?,?,?,?)`, c.ID, c.SessionID, c.Repository, string(b))
	return err
}

func (s *Store) checkpoints(session string) ([]ObservationCheckpoint, error) {
	rows, err := s.reader().Query(`SELECT record_json FROM ledger_checkpoints WHERE session_id=? ORDER BY id`, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []ObservationCheckpoint{}
	for rows.Next() {
		var data string
		var c ObservationCheckpoint
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}
