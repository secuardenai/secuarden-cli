package changeledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
)

type ProcessResult struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Conflicts  int `json:"conflicts"`
	Rejected   int `json:"rejected"`
	Replayed   int `json:"replayed"`
}

// ProcessInbox is explicitly separate from hook acknowledgement. The lock
// serializes workers, not producers. A crash releases the OS lock; SQLite's
// delivery key makes commit-before-unlink replay idempotent.
func (s *Store) ProcessInbox(dir string, limit int) (ProcessResult, error) {
	var result ProcessResult
	if limit < 1 || limit > 10000 {
		return result, fmt.Errorf("limit must be between 1 and 10000")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return result, err
	}
	if _, err := os.Stat(filepath.Join(dir, "inbox")); err != nil {
		gapErr := s.RecordGap(CoverageGap{Code: "inbox_unavailable", Source: "observation-processor", Detail: "Configured inbox cannot be read."})
		return result, errors.Join(err, gapErr)
	}
	lock, err := os.OpenFile(filepath.Join(dir, "process.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return result, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return result, fmt.Errorf("another observation processor is running: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	run := uuid.NewString()
	if err := s.beginObservationRun(run, dir); err != nil {
		return result, err
	}
	checkpoints := map[string]*ObservationCheckpoint{}
	processed := 0
	for _, directory := range []string{dir + "-failures", filepath.Join(dir, "inbox")} {
		entries, err := os.ReadDir(directory)
		if os.IsNotExist(err) && directory == dir+"-failures" {
			continue
		}
		if err != nil {
			return result, err
		}
		for _, entry := range entries {
			if processed >= limit {
				break
			}
			if !entry.Type().IsRegular() {
				continue
			}
			if strings.HasSuffix(entry.Name(), ".tmp") {
				if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) > time.Minute {
					if err := s.RecordGap(CoverageGap{Code: "incomplete_delivery", Source: "codex-inbox", ObservedAt: info.ModTime(), Detail: "Interrupted or stalled write: " + entry.Name()}); err != nil {
						return result, err
					}
				}
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			data, readErr := observationcapture.ReadBounded(path, observationcapture.MaxEnvelopeBytes)
			var e observationcapture.Envelope
			if readErr != nil || json.Unmarshal(data, &e) != nil || e.ID+".json" != entry.Name() {
				e = observationcapture.Envelope{ID: entry.Name(), ReceivedAt: time.Now().UTC(), Gap: "invalid_envelope"}
			}
			o, normalizationErr := observationcapture.Normalize(e)
			var observation *observationcapture.Observation
			if normalizationErr == nil {
				key := o.SessionID + "\x00" + o.CWD
				checkpoint, seen := checkpoints[key]
				if !seen {
					checkpoint, err = s.Checkpoint(o.CWD, o.SessionID, "processing")
					if err != nil {
						if errors.Is(err, errCheckpointStorage) {
							return result, err
						}
						checkpoint = nil
					}
					checkpoints[key] = checkpoint
				}
				if checkpoint != nil {
					o.Repository, o.RepositoryBasis = checkpoint.Repository, "git_at_processing_time"
				} else {
					o.Gaps = append(o.Gaps, "repository_unavailable")
				}
				observation = &o
			}
			reason := ""
			if normalizationErr != nil {
				reason = normalizationErr.Error()
			}
			disposition, err := s.saveDelivery(e, observation, reason)
			if err != nil {
				return result, err
			}
			switch disposition {
			case "accepted":
				result.Accepted++
			case "duplicate":
				result.Duplicates++
			case "conflict":
				result.Conflicts++
			case "rejected":
				result.Rejected++
			case "replayed":
				result.Replayed++
			}
			if err := os.Remove(path); err != nil {
				return result, err
			}
			processed++
		}
	}
	if err := s.finishObservationRun(run); err != nil {
		return result, err
	}
	return result, nil
}
