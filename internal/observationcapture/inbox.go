// Package observationcapture implements the independent, opt-in Codex inbox.
// Capture performs bounded I/O only. It never parses hook payloads, opens a
// database, executes Git, or contacts a service.
package observationcapture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

const Version = "codex-observation/v1"
const MaxInputBytes = 256 * 1024
const MaxEnvelopeBytes = 2 * MaxInputBytes
const ReadTimeout = 250 * time.Millisecond

var ErrDisabled = errors.New("observation capture is not enabled")

type Config struct {
	Version   string    `json:"version"`
	Enabled   bool      `json:"enabled"`
	Epoch     string    `json:"epoch"`
	EnabledAt time.Time `json:"enabled_at"`
	HookTrust string    `json:"hook_trust"` // unknown, untrusted, or operator_reported_trusted
}

// Envelope records receipt time, not a fabricated occurrence time. Payload is
// an opaque byte string so invalid JSON can be durably acknowledged too.
type Envelope struct {
	Version          string    `json:"version"`
	ID               string    `json:"id"`
	Epoch            string    `json:"epoch"`
	Event            string    `json:"event"`
	CollectorVersion string    `json:"collector_version"`
	ReceivedAt       time.Time `json:"received_at"`
	Payload          []byte    `json:"payload,omitempty"`
	Hash             string    `json:"hash"`
	Gap              string    `json:"gap,omitempty"`
}

func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".secuarden", "observations"), nil
}

func LoadConfig(dir string) (Config, error) {
	var c Config
	b, err := ReadBounded(filepath.Join(dir, "config.json"), 16*1024)
	if os.IsNotExist(err) {
		return c, ErrDisabled
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Version != Version || c.Epoch == "" {
		return c, fmt.Errorf("invalid capture configuration")
	}
	if !c.Enabled {
		return c, ErrDisabled
	}
	return c, nil
}

func Configure(dir string, enabled bool) (Config, error) {
	c, err := LoadConfig(dir)
	if err != nil && !errors.Is(err, ErrDisabled) {
		return c, err
	}
	if c.Epoch == "" || enabled && !c.Enabled {
		c = Config{Version: Version, Epoch: uuid.NewString(), EnabledAt: time.Now().UTC(), HookTrust: "unknown"}
	}
	c.Enabled = enabled
	if err := os.MkdirAll(filepath.Join(dir, "inbox"), 0700); err != nil {
		return c, err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return c, err
	}
	return c, WriteDurable(filepath.Join(dir, "config.json"), b)
}

// ReportTrust records an operator's report; it does not grant Codex hook trust.
func ReportTrust(dir, state string) error {
	if state != "unknown" && state != "untrusted" && state != "operator_reported_trusted" {
		return fmt.Errorf("trust must be unknown, untrusted, or operator_reported_trusted")
	}
	c, err := LoadConfig(dir)
	if err != nil {
		return err
	}
	c.HookTrust = state
	b, _ := json.Marshal(c)
	return WriteDurable(filepath.Join(dir, "config.json"), b)
}

func Capture(ctx context.Context, dir, event, collectorVersion string, input io.Reader) (Envelope, error) {
	c, err := LoadConfig(dir)
	if err != nil {
		return Envelope{}, err
	}
	e := Envelope{Version: Version, ID: uuid.NewString(), Epoch: c.Epoch, Event: event,
		CollectorVersion: collectorVersion, ReceivedAt: time.Now().UTC()}
	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() { b, err := io.ReadAll(io.LimitReader(input, MaxInputBytes+1)); read <- readResult{b, err} }()
	ctx, cancel := context.WithTimeout(ctx, ReadTimeout)
	defer cancel()
	select {
	case r := <-read:
		e.Payload = r.data
		if r.err != nil {
			e.Gap = "input_read_failed"
		}
		if len(e.Payload) > MaxInputBytes {
			e.Payload = e.Payload[:MaxInputBytes]
			e.Gap = "oversized_input"
		}
	case <-ctx.Done():
		e.Gap = "input_timeout"
	}
	e.Hash = Hash(e.Payload)
	b, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	if err := WriteDurable(filepath.Join(dir, "inbox", e.ID+".json"), b); err != nil {
		// Independent sibling diagnostics survive an unavailable inbox. Do not
		// retain raw payloads here or claim that the observation was captured.
		e.Payload, e.Gap = nil, "inbox_unavailable"
		b, _ = json.Marshal(e)
		if fallbackErr := WriteDurable(filepath.Join(dir+"-failures", e.ID+".json"), b); fallbackErr != nil {
			return e, fmt.Errorf("inbox unavailable; failure evidence also unavailable: %w", errors.Join(err, fallbackErr))
		}
		return e, fmt.Errorf("inbox unavailable; failure recorded: %w", err)
	}
	return e, nil
}

func Hash(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

func ReadBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("record exceeds size limit")
	}
	return b, nil
}

// WriteDurable makes success mean file data and its directory entry were
// synced. Interrupted .tmp files never become acknowledged deliveries.
func WriteDurable(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".capture-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
