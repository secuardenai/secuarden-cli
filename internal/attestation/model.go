// Package attestation records configuration observations, not proof of tool delivery.
// It has no dependency on capture, agent adapters, or reporting. Its local hash
// chain is a checksum; an owner of the machine can rewrite and recompute it.
package attestation

import "time"

const MaxObservationGap = 90 * time.Second

type ContractRef struct {
	Adapter string `json:"adapter"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}
type RequirementResult struct {
	ID     string `json:"id"`
	Status string `json:"status"` // pass, fail, unknown
	Reason string `json:"reason,omitempty"`
}
type Snapshot struct {
	Contracts  []ContractRef       `json:"contracts,omitempty"`
	Results    []RequirementResult `json:"results,omitempty"`
	Unknown    bool                `json:"unknown,omitempty"`
	Components map[string]string   `json:"components"`
	Problems   []string            `json:"problems,omitempty"`
}
type Observer func([]string) Snapshot

type State struct {
	Contracts     []ContractRef       `json:"contracts,omitempty"`
	Results       []RequirementResult `json:"results,omitempty"`
	Enabled       bool                `json:"enabled"`
	Agents        []string            `json:"agents"`
	Baseline      Snapshot            `json:"baseline"`
	BaselineID    string              `json:"baseline_id"`
	Configuration string              `json:"configuration"`
	LastObserved  time.Time           `json:"last_observed,omitempty"`
	LastMatching  time.Time           `json:"last_matching,omitempty"`
	Differences   []string            `json:"differences,omitempty"`
}
type Event struct {
	Sequence            int       `json:"sequence"`
	Kind                string    `json:"kind"`
	At                  time.Time `json:"observed_at"`
	PreviousObservation time.Time `json:"previous_observation,omitempty"`
	Reason              string    `json:"reason,omitempty"`
	Observation         *Snapshot `json:"observation,omitempty"`
	State               State     `json:"state"`
	PreviousHash        string    `json:"previous_hash"`
	Hash                string    `json:"hash"`
}
type Report struct {
	Status     string  `json:"status"`
	Scope      string  `json:"scope"`
	State      *State  `json:"state,omitempty"`
	History    []Event `json:"history"`
	Head       string  `json:"head,omitempty"`
	Error      string  `json:"error,omitempty"`
	Limitation string  `json:"limitation"`
}

const limitation = "Point-in-time configuration observations, not verified delivery. Changes between observations may be missed. Local checksum history can be rewritten by the machine owner."
