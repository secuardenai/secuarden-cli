package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"time"
)

// Apply serializes observation and state changes across independent CLI/monitor processes.
// Existing history is verified before appending. Compliance comes only from the embedded adapter contracts.
func (s *Store) Apply(action string, agents []string, reason string, now time.Time, observe Observer) (Report, error) {
	if action == "baseline" {
		return Report{}, fmt.Errorf("capture contracts are defined by the CLI; accepting a machine snapshot is no longer supported")
	}
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
		status, differences := evaluate(snapshot)
		changed := !reflect.DeepEqual(state.Contracts, snapshot.Contracts)
		kind := "checked"
		if changed {
			transition := "contract_changed"
			if len(state.Contracts) == 0 {
				transition = "contract_established"
				if state.BaselineID != "" {
					transition = "contract_migrated"
				}
			}
			state.Contracts = snapshot.Contracts
			// Record adoption separately, without certifying compliance.
			state.Configuration = "unknown"
			state.Results = nil
			state.Differences = nil
			if err := appendEvent(transition, &snapshot, previous); err != nil {
				return err
			}
		}
		if status != state.Configuration || !slices.Equal(differences, state.Differences) {
			kind = "deviation"
			if status == "satisfied" {
				kind = "restored"
				if changed {
					kind = "contract_satisfied"
				}
			}
			if status == "unknown" {
				kind = "observation_failed"
			}
		}
		state.Results = snapshot.Results

		state.Configuration = status
		state.Differences = differences
		state.LastObserved = now.UTC()
		if status == "satisfied" {
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
	case "enable":
		previousAgents := append([]string(nil), state.Agents...)
		// Enabling can add adapters, but cannot silently remove existing coverage.
		state.Agents = append(append([]string(nil), state.Agents...), agents...)
		sort.Strings(state.Agents)
		state.Agents = slices.Compact(state.Agents)
		if len(state.Agents) == 0 {
			return Report{}, fmt.Errorf("select at least one agent")
		}
		if !state.Enabled {
			state.Enabled = true
			err = appendEvent("enabled", nil, state.LastObserved)
		} else if !slices.Equal(previousAgents, state.Agents) {
			err = appendEvent("adapters_added", nil, state.LastObserved)
		}
		if err == nil {
			err = check()
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

// evaluate consumes requirement results, never equality with a saved machine state.
func evaluate(snapshot Snapshot) (string, []string) {
	differences := []string{}
	status := "satisfied"
	if len(snapshot.Contracts) == 0 || len(snapshot.Results) == 0 {
		status = "unknown"
		differences = append(differences, "adapter contract evaluation unavailable")
	}
	for _, result := range snapshot.Results {
		switch result.Status {
		case "pass":
		case "fail":
			if status != "unknown" {
				status = "violated"
			}
			differences = append(differences, result.ID+": "+result.Reason)
		default:
			status = "unknown"
			differences = append(differences, result.ID+": "+result.Reason)
		}
	}
	if snapshot.Unknown {
		status = "unknown"
	}
	sort.Strings(differences)
	return status, differences
}
