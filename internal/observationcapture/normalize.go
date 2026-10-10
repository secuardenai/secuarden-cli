package observationcapture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Observation retains structural evidence only, never tool arguments, prompt
// text, tool output, or transcript contents. No legacy event mapper is used.
type Observation struct {
	Version          string    `json:"version"`
	ID               string    `json:"id"`
	LogicalID        string    `json:"logical_id"`
	PayloadHash      string    `json:"payload_hash"`
	Epoch            string    `json:"epoch"`
	SessionID        string    `json:"session_id"`
	Event            string    `json:"event"`
	Tool             string    `json:"tool,omitempty"`
	InvocationID     string    `json:"invocation_id,omitempty"`
	ProcessID        string    `json:"process_id,omitempty"`
	Sequence         *int64    `json:"sequence,omitempty"`
	CWD              string    `json:"cwd"`
	Repository       string    `json:"repository,omitempty"`
	RepositoryBasis  string    `json:"repository_basis,omitempty"`
	OccurredAt       time.Time `json:"occurred_at"`
	ReceivedAt       time.Time `json:"received_at"`
	TimeBasis        string    `json:"time_basis"`
	Source           string    `json:"source"`
	SourceVersion    string    `json:"source_version"`
	CollectorVersion string    `json:"collector_version"`
	Outcome          string    `json:"outcome"`
	Paths            []string  `json:"paths"`
	Gaps             []string  `json:"gaps"`
}

var HookEvents = []string{"SessionStart", "SessionEnd", "PreToolUse", "PostToolUse", "PermissionRequest", "UserPromptSubmit", "Stop", "Interrupt", "PreCompact", "PostCompact"}

func SupportedEvent(event string) bool {
	for _, name := range HookEvents {
		if name == event {
			return true
		}
	}
	return false
}

func Normalize(e Envelope) (Observation, error) {
	o := Observation{Version: Version, Epoch: e.Epoch, ReceivedAt: e.ReceivedAt,
		OccurredAt: e.ReceivedAt, TimeBasis: "receipt", Source: "codex-hook",
		SourceVersion: "unknown", CollectorVersion: e.CollectorVersion,
		Outcome: "unknown", Paths: []string{}, Gaps: []string{}}
	if e.Gap != "" {
		return o, fmt.Errorf("%s", e.Gap)
	}
	if e.Version != Version || e.ID == "" || e.Epoch == "" || e.ReceivedAt.IsZero() || Hash(e.Payload) != e.Hash || len(e.Payload) > MaxInputBytes {
		return o, fmt.Errorf("invalid_envelope")
	}
	d := json.NewDecoder(bytes.NewReader(e.Payload))
	d.UseNumber()
	value, err := jsonValue(d, 0)
	if err != nil {
		return o, fmt.Errorf("malformed_input")
	}
	if _, err := d.Token(); err != io.EOF {
		return o, fmt.Errorf("malformed_input")
	}
	if _, ok := value.(map[string]interface{}); !ok {
		return o, fmt.Errorf("malformed_input")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return o, fmt.Errorf("malformed_input")
	}
	var raw struct {
		SessionID string          `json:"session_id"`
		CWD       string          `json:"cwd"`
		Event     string          `json:"hook_event_name"`
		EventID   string          `json:"event_id"`
		Timestamp string          `json:"timestamp"`
		Tool      string          `json:"tool_name"`
		ToolID    string          `json:"tool_use_id"`
		TurnID    string          `json:"turn_id"`
		ProcessID string          `json:"process_id"`
		Sequence  *int64          `json:"sequence"`
		Source    string          `json:"source"`
		Version   string          `json:"codex_version"`
		Input     json.RawMessage `json:"tool_input"`
		Response  json.RawMessage `json:"tool_response"`
	}
	if err := json.Unmarshal(canonical, &raw); err != nil {
		return o, fmt.Errorf("malformed_input")
	}
	if raw.SessionID == "" || len(raw.SessionID) > 512 || !filepath.IsAbs(raw.CWD) || strings.ContainsRune(raw.CWD, 0) {
		return o, fmt.Errorf("missing_identity")
	}
	if raw.Event != e.Event || !SupportedEvent(raw.Event) {
		return o, fmt.Errorf("unsupported_or_mismatched_hook")
	}
	o.SessionID, o.CWD, o.Event = raw.SessionID, filepath.Clean(raw.CWD), raw.Event
	o.Tool, o.InvocationID, o.ProcessID, o.Sequence = raw.Tool, raw.ToolID, raw.ProcessID, raw.Sequence
	if raw.Version != "" {
		o.SourceVersion = raw.Version
	}
	if raw.Timestamp != "" {
		at, err := time.Parse(time.RFC3339Nano, raw.Timestamp)
		if err != nil {
			o.Gaps = append(o.Gaps, "invalid_timestamp")
		} else {
			o.OccurredAt, o.TimeBasis = at.UTC(), "source"
			if e.ReceivedAt.Sub(at) > 30*time.Second {
				o.Gaps = append(o.Gaps, "delayed_input")
			}
			if at.After(e.ReceivedAt.Add(5 * time.Second)) {
				o.Gaps = append(o.Gaps, "clock_skew")
			}
		}
	} else {
		o.Gaps = append(o.Gaps, "occurrence_time_unavailable")
	}
	if raw.Sequence != nil && *raw.Sequence < 0 {
		return o, fmt.Errorf("invalid_sequence")
	}
	if raw.Event == "SessionStart" && raw.Source == "resume" {
		o.Gaps = append(o.Gaps, "process_restart") // continuity across resume is unproven
	}
	if raw.Event == "PreToolUse" || raw.Event == "PostToolUse" {
		if raw.ToolID == "" {
			o.Gaps = append(o.Gaps, "invocation_id_unavailable")
		}
	}
	// Missing timestamps/IDs remain explicit. Canonically identical anonymous
	// inputs coalesce, but every delivery is retained and ambiguity is exposed.
	o.PayloadHash = Hash(canonical)
	key := raw.EventID
	if key == "" && raw.ToolID != "" {
		key = raw.ToolID + "\x00" + raw.TurnID
	}
	if key == "" {
		key = o.PayloadHash
		o.Gaps = append(o.Gaps, "event_identity_unavailable")
	}
	o.LogicalID = Hash([]byte(e.Epoch + "\x00" + raw.CWD + "\x00" + raw.SessionID + "\x00" + raw.Event + "\x00" + key))
	o.ID = Hash([]byte(o.LogicalID + "\x00" + o.PayloadHash))
	var input map[string]interface{}
	_ = json.Unmarshal(raw.Input, &input)
	paths := map[string]bool{}
	for _, key := range []string{"path", "file_path"} {
		if path, ok := input[key].(string); ok && path != "" {
			paths[path] = true
		}
	}
	if raw.Tool == "apply_patch" {
		patch, _ := input["input"].(string)
		if patch == "" {
			patch, _ = input["patch"].(string)
		}
		if patch == "" {
			_ = json.Unmarshal(raw.Input, &patch)
		}
		for _, line := range strings.Split(patch, "\n") {
			for _, prefix := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
				if strings.HasPrefix(line, prefix) {
					paths[strings.TrimPrefix(line, prefix)] = true
				}
			}
		}
	}
	for path := range paths {
		if path != "" && len(path) <= 4096 && !strings.ContainsRune(path, 0) {
			o.Paths = append(o.Paths, filepath.ToSlash(filepath.Clean(path)))
		}
	}
	sort.Strings(o.Paths)
	if raw.Event == "PostToolUse" {
		var response struct {
			ExitCode *int  `json:"exit_code"`
			Success  *bool `json:"success"`
		}
		if json.Unmarshal(raw.Response, &response) == nil {
			if response.ExitCode != nil {
				if *response.ExitCode == 0 {
					o.Outcome = "success"
				} else {
					o.Outcome = "failed"
				}
			}
			if response.Success != nil {
				if *response.Success {
					o.Outcome = "success"
				} else {
					o.Outcome = "failed"
				}
			}
		}
		if response.ExitCode != nil && response.Success != nil && (*response.ExitCode == 0) != *response.Success {
			o.Outcome = "unknown"
			o.Gaps = append(o.Gaps, "conflicting_outcome")
		}
		if o.Outcome == "unknown" {
			o.Gaps = append(o.Gaps, "outcome_unavailable")
		}
	}
	return o, nil
}

// Reject duplicate keys instead of accepting last-key-wins identities.
func jsonValue(d *json.Decoder, depth int) (interface{}, error) {
	if depth > 64 {
		return nil, fmt.Errorf("too deeply nested")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := map[string]interface{}{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("invalid key")
			}
			if _, exists := object[name]; exists {
				return nil, fmt.Errorf("duplicate key")
			}
			value, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		_, err := d.Token()
		return object, err
	case json.Delim('['):
		array := []interface{}{}
		for d.More() {
			value, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		_, err := d.Token()
		return array, err
	default:
		if _, ok := token.(json.Delim); ok {
			return nil, fmt.Errorf("unexpected delimiter")
		}
		return token, nil
	}
}
