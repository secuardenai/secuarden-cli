package storage

// IntegrityFinding describes a failed check. Sequence is omitted for session checks.
type IntegrityFinding struct {
	SessionID string `json:"session_id"`
	Sequence  int    `json:"sequence,omitempty"`
	Agent     string `json:"agent"`
	Kind      string `json:"kind"`
}

func (r *IntegrityResult) addFinding(session string, sequence int, agent, kind string) {
	r.Findings = append(r.Findings, IntegrityFinding{session, sequence, agent, kind})
}
