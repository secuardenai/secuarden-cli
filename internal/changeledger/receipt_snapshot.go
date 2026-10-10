package changeledger

import (
	"database/sql"
	"fmt"
	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
	"sort"
	"unicode/utf8"
)

type ledgerReader interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func (s *Store) reader() ledgerReader {
	if s.readTx != nil {
		return s.readTx
	}
	return s.db
}

// ReceiptSnapshot reads attribution and its source rows from one database snapshot.
// Runtime inbox inspection is performed separately by the caller.
func (s *Store) ReceiptSnapshot(digest string) (*Coverage, []observationcapture.Observation, []ObservationCheckpoint, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()
	view := &Store{db: s.db, path: s.path, readTx: tx}
	coverage, err := view.Coverage(digest)
	if err != nil {
		return nil, nil, nil, err
	}
	observations := []observationcapture.Observation{}
	checkpoints := []ObservationCheckpoint{}
	for _, scope := range coverage.Scopes {
		obs, err := view.Observations(scope.SessionID)
		if err != nil {
			return nil, nil, nil, err
		}
		observations = append(observations, obs...)
		cps, err := view.checkpoints(scope.SessionID)
		if err != nil {
			return nil, nil, nil, err
		}
		checkpoints = append(checkpoints, cps...)
	}
	sort.Slice(observations, func(i, j int) bool { return observations[i].ID < observations[j].ID })
	sort.Slice(checkpoints, func(i, j int) bool { return checkpoints[i].ID < checkpoints[j].ID })
	sort.Slice(coverage.Links, func(i, j int) bool {
		if coverage.Links[i].ObservationID == coverage.Links[j].ObservationID {
			return coverage.Links[i].SessionID < coverage.Links[j].SessionID
		}
		return coverage.Links[i].ObservationID < coverage.Links[j].ObservationID
	})
	return coverage, observations, checkpoints, nil
}

// VerifyChange preserves the frozen changeledger/v1 digest projection.
func VerifyChange(c *Change) error {
	if c == nil || c.Status != "complete" || c.Version != ContractVersion || c.Digest == "" {
		return fmt.Errorf("incomplete change")
	}
	if !utf8.ValidString(c.Repository) {
		return fmt.Errorf("invalid repository Unicode")
	}
	for _, p := range c.ChangedPaths {
		if !utf8.ValidString(p.Path) || !utf8.ValidString(p.OldPath) {
			return fmt.Errorf("invalid path Unicode")
		}
	}
	copy := *c
	if err := copy.setDigest(); err != nil {
		return err
	}
	if copy.Digest != c.Digest {
		return fmt.Errorf("change digest mismatch")
	}
	return nil
}
