// Package live evaluates persisted capture metadata; it never invokes hooks.
package live

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

type State struct {
	Started         time.Time  `json:"started"`
	Watermark       int64      `json:"watermark"`
	Agent           string     `json:"agent"`
	Repository      string     `json:"repository"`
	RequestedClient string     `json:"requested_client"`
	Fingerprint     string     `json:"fingerprint"`
	Runtime         string     `json:"detected_runtime,omitempty"`
	CLIVersion      string     `json:"cli_version"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty"`
	Session         string     `json:"session,omitempty"`
	AgentVersion    string     `json:"observed_agent_version,omitempty"`
	Evidence        []string   `json:"evidence,omitempty"`
	Stage           string     `json:"stage"`
}

func Key(agent, repo string) string {
	return fmt.Sprintf("live_verification_%x", sha256.Sum256([]byte(agent+"\x00"+repo)))
}

// Evaluate requires a caller-selected fresh session and a correlated pre/post
// pair. Both currently supported agents provide these hooks; neither needs exit.
func Evaluate(s State, records []storage.LiveRecord, old bool, failures int) (string, []string, string) {
	if old {
		return "session_not_fresh", nil, ""
	}
	if failures > 0 {
		return "capture_persistence_failure", nil, ""
	}
	pre := map[string]storage.LiveRecord{}
	post := map[string]storage.LiveRecord{}
	var observed []string
	startID := ""
	for _, r := range records {
		if r.Agent != s.Agent || r.Session != s.Session {
			continue
		}
		captured, err := time.Parse(time.RFC3339Nano, r.CapturedAt)
		if err != nil || captured.Before(s.Started) {
			continue
		}
		root, err := repository.ResolvePath(r.Directory)
		if err != nil || !root.RootValid || root.Root != s.Repository {
			continue
		}
		observed = append(observed, r.ID)
		if r.Phase == "session_start" {
			startID = r.ID
		}
		if r.Invocation == "" || r.Tool == "" {
			continue
		}
		key := r.Invocation + "\x00" + r.Tool
		if r.Phase == "pre" {
			pre[key] = r
		}
		if r.Phase == "post" {
			post[key] = r
		}
	}
	if startID == "" && len(observed) > 0 {
		return "fresh_session_start_missing", nil, ""
	}
	for k, p := range pre {
		if q, ok := post[k]; ok {
			version := q.Version
			if version == "" {
				version = p.Version
			}
			return "tool_round_trip", []string{startID, p.ID, q.ID}, version
		}
	}
	if len(pre) > 0 {
		return "request_received_result_missing", nil, ""
	}
	if len(observed) > 0 {
		return "events_received_round_trip_pending", nil, ""
	}
	return "no_matching_event", nil, ""
}
