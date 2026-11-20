package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"
)

// Apply serializes observation and state changes across independent CLI/monitor processes.
// Existing history is verified before appending; no operation silently rebaselines.
func (s *Store) Apply(action string, agents []string, reason string, now time.Time, observe Observer) (Report, error) {
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return Report{}, err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return Report{}, err
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	events, err := load(conn)
	if err != nil {
		return Report{}, err
	}
	state := State{Configuration: "not_configured"}
	if len(events) > 0 {
		state = events[len(events)-1].State
	}
	appendEvent := func(kind string, snapshot *Snapshot, previous time.Time) error {
		e := Event{Sequence: len(events) + 1, Kind: kind, At: now.UTC(), PreviousObservation: previous, Reason: reason, Observation: snapshot, State: state}
		if len(events) > 0 {
			e.PreviousHash = events[len(events)-1].Hash
		}
		hash := digest(e)
		body, _ := json.Marshal(e)
		if _, err := conn.ExecContext(context.Background(), "INSERT INTO configuration_attestation VALUES (?,?,?)", e.Sequence, string(body), hash); err != nil {
			return err
		}
		e.Hash = hash
		events = append(events, e)
		return nil
	}
	check := func() error {
		if !state.Enabled {
			return nil
		}
		previous := state.LastObserved
		if !previous.IsZero() && (now.Sub(previous) > MaxObservationGap || now.Before(previous)) {
			if err := appendEvent("observation_gap", nil, previous); err != nil {
				return err
			}
		}
		snapshot := observe(state.Agents)
		differences := diff(state.Baseline, snapshot)
		status := "matches"
		if snapshot.Unknown {
			status = "unknown"
		} else if len(differences) > 0 {
			status = "deviated"
		}
		kind := "checked"
		if status != state.Configuration || !slices.Equal(differences, state.Differences) {
			kind = "deviation"
			if status == "matches" {
				kind = "restored"
			}
			if status == "unknown" {
				kind = "observation_failed"
			}
		}
		state.Configuration = status
		state.Differences = differences
		state.LastObserved = now.UTC()
		if status == "matches" {
			state.LastMatching = now.UTC()
		}
		return appendEvent(kind, &snapshot, previous)
	}
	switch action {
	case "check":
		err = check()
	case "disable":
		if state.Enabled {
			if err = check(); err == nil {
				state.Enabled = false
				err = appendEvent("disabled", nil, state.LastObserved)
			}
		} else if len(events) == 0 {
			err = appendEvent("disabled", nil, time.Time{})
		}
	case "enable", "baseline":
		if action == "baseline" && reason == "" {
			return Report{}, fmt.Errorf("baseline requires a reason")
		}
		if state.BaselineID != "" && action == "enable" {
			if !state.Enabled {
				state.Enabled = true
				err = appendEvent("enabled", nil, state.LastObserved)
			}
			if err == nil {
				err = check()
			}
		} else {
			if len(agents) == 0 {
				agents = state.Agents
			}
			if len(agents) == 0 {
				return Report{}, fmt.Errorf("select at least one agent")
			}
			if state.Enabled {
				if err = check(); err != nil {
					return Report{}, err
				}
			}
			snapshot := observe(agents)
			if snapshot.Unknown || len(snapshot.Problems) > 0 || len(snapshot.Components) == 0 {
				// Keep observations made during a rejected rebaseline attempt.
				if err = appendEvent("baseline_rejected", &snapshot, state.LastObserved); err != nil {
					return Report{}, err
				}
				if _, err = conn.ExecContext(context.Background(), "COMMIT"); err != nil {
					return Report{}, err
				}
				return summarize(events, now), fmt.Errorf("cannot establish baseline: %v", snapshot.Problems)
			}
			sort.Strings(agents)
			state = State{Enabled: true, Agents: agents, Baseline: snapshot, BaselineID: digest(snapshot), Configuration: "matches", LastObserved: now.UTC(), LastMatching: now.UTC()}
			err = appendEvent("baseline", &snapshot, time.Time{})
		}
	default:
		return Report{}, fmt.Errorf("unknown attestation action %q", action)
	}
	if err != nil {
		return Report{}, err
	}
	if _, err = conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return Report{}, err
	}
	return summarize(events, now), nil
}
func diff(a, b Snapshot) []string {
	changes := []string{}
	for k, v := range a.Components {
		if b.Components[k] != v {
			changes = append(changes, k)
		}
	}
	for k := range b.Components {
		if _, ok := a.Components[k]; !ok {
			changes = append(changes, k)
		}
	}
	changes = append(changes, b.Problems...)
	sort.Strings(changes)
	return changes
}
