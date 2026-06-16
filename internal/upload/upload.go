// Package upload sends a completed session summary to the Secuarden SaaS
// and returns developer feedback from the changeset evaluator.
// Only called when sync_enabled = true in ~/.secuarden/config.json.
package upload

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/secuarden/secuarden-cli/internal/config"
	"github.com/secuarden/secuarden-cli/internal/storage"
)

// Feedback is the subset of the session-sync response shown to the developer.
type Feedback struct {
	Decision  string  `json:"decision"`
	RiskLevel string  `json:"risk_level"`
	RiskScore float64 `json:"risk_score"`
	Summary   string  `json:"summary"`
	Branch    string  `json:"branch"`
	SessionsN int     `json:"sessions_in_changeset"`
}

// StoredFeedback is written to ~/.secuarden/last-feedback.json so that
// `secuarden status` can surface it regardless of how the session was run
// (terminal, IDE extension, background task).
type StoredFeedback struct {
	Feedback
	SessionID   string `json:"session_id"`
	CapturedAt  string `json:"captured_at"`
}

// LastFeedbackPath returns ~/.secuarden/last-feedback.json.
func LastFeedbackPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".secuarden", "last-feedback.json"), nil
}

// WriteFeedback persists feedback to disk so it survives the process exit.
func WriteFeedback(f *Feedback, sessionID string) {
	path, err := LastFeedbackPath()
	if err != nil {
		return
	}
	sf := StoredFeedback{
		Feedback:   *f,
		SessionID:  sessionID,
		CapturedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, append(data, '\n'), 0600)
}

// ReadLastFeedback reads the stored feedback file if it exists.
func ReadLastFeedback() *StoredFeedback {
	path, err := LastFeedbackPath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var sf StoredFeedback
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil
	}
	return &sf
}

// SyncSession posts the session summary to /api/agent-ledger/session-sync
// and returns developer feedback if the changeset evaluator responds.
// Never returns a hard error — upload failures are non-fatal.
func SyncSession(cfg *config.Config, summary *storage.SessionSummary) (*Feedback, error) {
	if !cfg.SyncEnabled || cfg.APIKey == "" {
		return nil, nil
	}

	body, err := json.Marshal(summary)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	url := cfg.APIURL + "/api/agent-ledger/session-sync"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST session-sync: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("session-sync %d: %s", resp.StatusCode, string(raw))
	}

	var result struct {
		Changeset *Feedback `json:"changeset"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return result.Changeset, nil
}
