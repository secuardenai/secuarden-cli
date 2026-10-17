package changereceipt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/config"
)

const ReceiptsPath = "/api/change-ledger/v1/receipts"

// TerminalUploadError requires a configuration or server correction before retry.
type TerminalUploadError struct{ Err error }

func (e *TerminalUploadError) Error() string { return e.Err.Error() }
func terminal(err error) error               { return &TerminalUploadError{Err: err} }

type UploadAcknowledgement struct {
	ReceiptID         string `json:"receipt_id"`
	ReceiptIntegrity  string `json:"receipt_integrity"`
	EvidenceIntegrity string `json:"evidence_integrity"`
	RevisionMatch     string `json:"revision_match"`
	CoverageState     string `json:"coverage_state"`
	ReceivedAt        string `json:"received_at"`
	InspectionURL     string `json:"inspection_url"`
}

func Upload(ctx context.Context, cfg *config.Config, a *Artifact, client *http.Client) ([]byte, error) {
	if err := a.Verify(); err != nil {
		return nil, terminal(err)
	}
	if cfg == nil || !cfg.SyncEnabled || strings.TrimSpace(cfg.APIKey) == "" {
		return nil, terminal(fmt.Errorf("repository SaaS integration required"))
	}
	u, err := url.Parse(cfg.APIURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, terminal(fmt.Errorf("upload requires an HTTPS API URL"))
	}
	u.Path = strings.TrimRight(u.Path, "/") + ReceiptsPath
	u.RawPath = ""
	raw, err := canonicalObject(a.Envelope)
	if err != nil {
		return nil, terminal(err)
	}
	if len(raw) > MaxEnvelope {
		return nil, terminal(fmt.Errorf("receipt exceeds 10 MiB upload limit"))
	}
	if client == nil {
		client = &http.Client{}
	}
	safe := *client
	safe.Timeout = 5 * time.Second
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	delays := []time.Duration{0, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	nextDelay := time.Duration(0)
	last := "receipt upload pending"
	for attempt := 0; attempt < 5; attempt++ {
		delay := delays[attempt]
		if nextDelay > delay {
			delay = nextDelay
		}
		nextDelay = 0
		if delay > 0 {
			if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= delay {
				return nil, fmt.Errorf("upload retry budget exhausted")
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, fmt.Errorf("upload retry budget exhausted")
			case <-timer.C:
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(raw))
		if err != nil {
			return nil, terminal(fmt.Errorf("build receipt upload request"))
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(cfg.APIKey))
		resp, err := safe.Do(req)
		if err != nil {
			last = "receipt upload failed (network or TLS error)"
			if ctx.Err() != nil {
				break
			}
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
		resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			if readErr != nil || len(body) > 64*1024 {
				return nil, terminal(fmt.Errorf("invalid receipt upload response"))
			}
			var ack UploadAcknowledgement
			if json.Unmarshal(body, &ack) != nil || ack.ReceiptID != a.Payload().ReceiptID || ack.ReceiptIntegrity != "verified" || ack.EvidenceIntegrity != "verified" {
				return nil, terminal(fmt.Errorf("invalid receipt upload acknowledgement identity or integrity"))
			}
			stamp, err := time.Parse(time.RFC3339Nano, ack.ReceivedAt)
			link, linkErr := url.Parse(ack.InspectionURL)
			if err != nil || stamp.IsZero() || !strings.HasSuffix(ack.ReceivedAt, "Z") || linkErr != nil || link.Scheme != "https" || link.Host != u.Host || link.User != nil || (ack.RevisionMatch != "pending" && ack.RevisionMatch != "verified" && ack.RevisionMatch != "mismatch") || (ack.CoverageState != "unobserved" && ack.CoverageState != "partial" && ack.CoverageState != "complete") {
				return nil, terminal(fmt.Errorf("invalid receipt upload acknowledgement metadata"))
			}
			return body, nil
		}
		last = fmt.Sprintf("receipt upload failed (HTTP %d)", resp.StatusCode)
		if resp.StatusCode != 408 && resp.StatusCode != 429 && (resp.StatusCode < 500 || resp.StatusCode > 599) {
			return nil, terminal(fmt.Errorf("%s", last))
		}
		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			v := resp.Header.Get("Retry-After")
			if seconds, err := strconv.ParseInt(v, 10, 32); err == nil && seconds >= 0 {
				nextDelay = time.Duration(seconds) * time.Second
			} else if when, err := http.ParseTime(v); err == nil {
				nextDelay = time.Until(when)
			}
		}
	}
	return nil, fmt.Errorf("%s; retry with secuarden ledger receipt upload %s", last, a.Payload().ReceiptID)
}
