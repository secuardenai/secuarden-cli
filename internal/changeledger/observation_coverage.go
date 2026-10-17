package changeledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
)

type ObservationScope struct {
	SessionID string    `json:"session_id"`
	Since     time.Time `json:"since"`
	Until     time.Time `json:"until"`
}
type ObservationLink struct {
	Version       string   `json:"version"`
	ChangeDigest  string   `json:"change_digest"`
	ObservationID string   `json:"observation_id"`
	SessionID     string   `json:"session_id"`
	Event         string   `json:"event"`
	Confidence    string   `json:"confidence"`
	Evidence      []string `json:"evidence"`
	Reasons       []string `json:"reasons"`
	Source        string   `json:"source"`
	SourceVersion string   `json:"source_version"`
}
type Coverage struct {
	Version      string             `json:"version"`
	ChangeDigest string             `json:"change_digest"`
	State        string             `json:"state"`
	Reasons      []CoverageGap      `json:"reasons"`
	Scopes       []ObservationScope `json:"scopes"`
	Links        []ObservationLink  `json:"inferred_links"`
	Matched      int                `json:"matched"`
	Unmatched    int                `json:"unmatched"`
	Duplicates   int                `json:"duplicates"`
	Conflicts    int                `json:"conflicts"`
	Pending      int                `json:"pending"`
}

func (c *Coverage) reason(code, session, detail string) {
	for _, g := range c.Reasons {
		if g.Code == code && g.SessionID == session {
			return
		}
	}
	c.Reasons = append(c.Reasons, CoverageGap{Version: ContractVersion, Code: code, SessionID: session, Source: "coverage-analysis", SourceVersion: observationcapture.Version, ObservedAt: time.Now().UTC(), Detail: detail})
}

func (s *Store) Correlate(digest string, scope ObservationScope) (*Coverage, error) {
	if _, _, err := s.Get(digest); err != nil {
		return nil, err
	}
	if scope.SessionID == "" || scope.Since.IsZero() || !scope.Until.After(scope.Since) {
		return nil, fmt.Errorf("session and an ordered, explicit time window are required")
	}
	_, err := s.db.Exec(`INSERT INTO change_observation_scopes VALUES(?,?,?,?) ON CONFLICT(change_digest,session_id) DO UPDATE SET since=excluded.since,until=excluded.until`, digest, scope.SessionID, scope.Since.UTC().Format(time.RFC3339Nano), scope.Until.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	return s.Coverage(digest)
}
func (s *Store) scopes(digest string) ([]ObservationScope, error) {
	rows, err := s.reader().Query(`SELECT session_id,since,until FROM change_observation_scopes WHERE change_digest=? ORDER BY session_id`, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []ObservationScope{}
	for rows.Next() {
		var scope ObservationScope
		var since, until string
		if err := rows.Scan(&scope.SessionID, &since, &until); err != nil {
			return nil, err
		}
		scope.Since, err = time.Parse(time.RFC3339Nano, since)
		if err != nil {
			return nil, err
		}
		scope.Until, err = time.Parse(time.RFC3339Nano, until)
		if err != nil {
			return nil, err
		}
		result = append(result, scope)
	}
	return result, rows.Err()
}

// Coverage recomputes attribution from immutable observations so late arrivals
// can resolve earlier gaps. It cannot certify exhaustive agent coverage.
func (s *Store) Coverage(digest string) (*Coverage, error) {
	change, _, err := s.Get(digest)
	if err != nil {
		return nil, err
	}
	scopes, err := s.scopes(digest)
	if err != nil {
		return nil, err
	}
	all, err := s.Observations("")
	if err != nil {
		return nil, err
	}
	c := &Coverage{Version: ContractVersion, ChangeDigest: digest, State: "unobserved", Scopes: scopes, Links: []ObservationLink{}, Reasons: []CoverageGap{}}
	sessions := map[string]bool{}
	if len(scopes) == 0 {
		c.reason("change_scope_missing", "", "No session and time window have been associated with this exact revision.")
	}
	for _, scope := range scopes {
		sessions[scope.SessionID] = true
		cps, err := s.checkpoints(scope.SessionID)
		if err != nil {
			return nil, err
		}
		obs := []observationcapture.Observation{}
		identities := map[string]int{}
		for _, o := range all {
			if o.SessionID == scope.SessionID {
				obs = append(obs, o)
				identities[o.LogicalID]++
			}
		}
		sort.Slice(obs, func(i, j int) bool {
			if obs[i].ReceivedAt.Equal(obs[j].ReceivedAt) {
				return obs[i].ID < obs[j].ID
			}
			return obs[i].ReceivedAt.Before(obs[j].ReceivedAt)
		})
		start, end := false, false
		pre, post := map[string]bool{}, map[string]bool{}
		processes := map[string]bool{}
		var latest time.Time
		var seq *int64
		for _, o := range obs {
			l := ObservationLink{Version: ContractVersion, ChangeDigest: digest, ObservationID: o.ID, SessionID: o.SessionID, Event: o.Event, Confidence: "unmatched", Evidence: []string{"session"}, Reasons: []string{}, Source: "repository-session-time-checkpoints", SourceVersion: observationcapture.Version}
			eligible := o.Repository == change.Repository && !o.OccurredAt.Before(scope.Since) && !o.OccurredAt.After(scope.Until)
			if o.Repository != change.Repository {
				l.Reasons = append(l.Reasons, "repository_mismatch_or_unavailable")
			}
			if o.OccurredAt.Before(scope.Since) || o.OccurredAt.After(scope.Until) {
				l.Reasons = append(l.Reasons, "outside_change_window")
			}
			if identities[o.LogicalID] > 1 {
				eligible = false
				l.Reasons = append(l.Reasons, "conflicting_delivery")
				c.reason("conflicting_delivery", o.SessionID, "Different payloads claimed the same event identity; neither is trusted for attribution.")
			}
			if eligible {
				l.Confidence = "low"
				l.Evidence = append(l.Evidence, "repository_at_processing_time", "explicit_time_window")
				base, head := false, false
				for _, cp := range cps {
					if cp.Repository != change.Repository || !insideRoot(cp.Root, o.CWD) {
						continue
					}
					if cp.Kind == "start" && cp.Commit == change.BaseCommit && cp.Tree == change.BaseTree && !cp.ObservedAt.After(o.OccurredAt) {
						base = true
					}
					if cp.Kind == "end" && cp.Commit == change.HeadCommit && cp.Tree == change.HeadTree && !cp.ObservedAt.Before(o.OccurredAt) {
						head = true
					}
				}
				if base && head {
					l.Confidence = "medium"
					l.Evidence = append(l.Evidence, "exact_base_start_checkpoint", "exact_head_end_checkpoint")
					if o.TimeBasis == "source" && !hasReason(o.Gaps, "clock_skew") {
						l.Confidence = "high"
					}
				} else {
					l.Reasons = append(l.Reasons, "checkpoint_evidence_missing")
					c.reason("checkpoint_evidence_missing", o.SessionID, "Exact base and head checkpoints bracketing the observation are unavailable.")
				}
				if o.Event == "SessionStart" {
					start = true
				}
				if o.Event == "SessionEnd" {
					end = true
				}
				if o.ProcessID != "" {
					processes[o.ProcessID] = true
				}
				if o.TimeBasis == "source" {
					if !latest.IsZero() && o.OccurredAt.Before(latest) {
						c.reason("out_of_order", o.SessionID, "Source occurrence order differs from delivery order.")
					}
					if o.OccurredAt.After(latest) {
						latest = o.OccurredAt
					}
				}
				if o.Sequence != nil {
					if seq != nil {
						if *o.Sequence < *seq {
							c.reason("out_of_order", o.SessionID, "Source sequence arrived out of order.")
						}
						if *o.Sequence > *seq+1 {
							c.reason("sequence_gap", o.SessionID, "Source sequence contains an unexplained jump.")
						}
					}
					if seq == nil || *o.Sequence > *seq {
						v := *o.Sequence
						seq = &v
					}
				}
				if o.InvocationID != "" {
					key := o.InvocationID + "\x00" + o.Tool
					if o.Event == "PreToolUse" {
						pre[key] = true
					}
					if o.Event == "PostToolUse" {
						post[key] = true
						if !pre[key] {
							c.reason("out_of_order", o.SessionID, "A tool result arrived before its corresponding start.")
						}
					}
				}
				c.Matched++
			} else {
				c.Unmatched++
				c.reason("unmatched_observations", o.SessionID, "Some observations cannot be attributed to this repository and revision window.")
			}
			for _, g := range o.Gaps {
				c.reason(g, o.SessionID, "Reported by the independent observation normalizer.")
			}
			duplicates, conflicts, err := s.deliveryCounts(o.ID)
			if err != nil {
				return nil, err
			}
			c.Duplicates += duplicates
			c.Conflicts += conflicts
			if duplicates > 0 {
				c.reason("duplicate_delivery", o.SessionID, "Repeated delivery was retained for audit and normalized once.")
			}
			c.Links = append(c.Links, l)
		}
		if !start {
			c.reason("missed_start", scope.SessionID, "No eligible SessionStart observation was captured.")
		}
		if !end {
			c.reason("missed_end", scope.SessionID, "No eligible SessionEnd observation was captured; Stop is a turn boundary.")
		}
		if len(processes) > 1 {
			c.reason("process_restart", scope.SessionID, "Multiple process identities were observed; continuity is unproven.")
		}
		for id := range pre {
			if !post[id] {
				c.reason("missing_tool_result", scope.SessionID, "A tool start has no matching result.")
			}
		}
		for id := range post {
			if !pre[id] {
				c.reason("missing_tool_start", scope.SessionID, "A tool result has no matching start.")
			}
		}
	}
	for _, o := range all {
		if !sessions[o.SessionID] && (o.Repository == change.Repository || o.Repository == "") {
			c.Unmatched++
			c.reason("unmatched_observations", o.SessionID, "No explicit session scope links this observation to the revision.")
		}
	}
	gaps, err := s.storedGaps()
	if err != nil {
		return nil, err
	}
	for _, g := range gaps {
		if g.SessionID == "" || sessions[g.SessionID] {
			c.Reasons = append(c.Reasons, g)
		}
	}
	if c.Matched > 0 {
		c.State = "partial"
	} else {
		c.reason("no_matching_observations", "", "No attributable observations were captured.")
	}
	c.reason("coverage_not_proven", "", "Hook observations do not establish exhaustive coverage or code authorship.")
	if s.readTx != nil {
		return c, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM change_observation_links WHERE change_digest=?`, digest); err != nil {
		return nil, err
	}
	for _, l := range c.Links {
		b, err := json.Marshal(l)
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`INSERT INTO change_observation_links VALUES(?,?,?)`, digest, l.ObservationID, string(b)); err != nil {
			return nil, err
		}
	}
	return c, tx.Commit()
}
func hasReason(reasons []string, code string) bool {
	for _, r := range reasons {
		if r == code {
			return true
		}
	}
	return false
}
func insideRoot(root, path string) bool {
	// Git resolves filesystem aliases such as macOS /var -> /private/var.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// InspectInbox adds current collection uncertainty to historical coverage.
// Operator-reported trust is not treated as proof of runtime hook execution.
func (c *Coverage) InspectInbox(dir string) {
	cfg, err := observationcapture.LoadConfig(dir)
	if errors.Is(err, observationcapture.ErrDisabled) {
		c.reason("capture_disabled", "", "The independent capture is not enabled.")
	} else if err != nil {
		c.reason("inbox_unavailable", "", "Capture configuration cannot be read.")
	}
	if cfg.HookTrust == "untrusted" {
		c.reason("untrusted_hooks", "", "The operator reports that Codex has not trusted these hooks.")
	}
	c.reason("hook_trust_unverified", "", "Codex runtime trust has not been independently verified.")
	for _, path := range []string{filepath.Join(dir, "inbox"), dir + "-failures"} {
		entries, err := os.ReadDir(path)
		if os.IsNotExist(err) && path == dir+"-failures" {
			continue
		}
		if err != nil {
			c.reason("inbox_unavailable", "", "An observation inbox cannot be inspected.")
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") {
				c.Pending++
			}
			if strings.HasSuffix(e.Name(), ".tmp") {
				c.reason("incomplete_delivery", "", "An incomplete inbox write exists.")
			}
		}
	}
	if c.Pending > 0 {
		c.reason("pending_inputs", "", "Durable inputs await separate normalization.")
	}
}
