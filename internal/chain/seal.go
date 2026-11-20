package chain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/attestation"
	"github.com/secuardenai/secuarden-cli/internal/changereceipt"
	"github.com/secuardenai/secuarden-cli/internal/config"
)

const ProtocolVersion = "secuarden.chain/v1"
const sealsPath = "/api/change-ledger/v1/chain-seals"

// HTTPClient is the client used to register a key and upload a seal.
// Tests replace it with a server-specific client.
var HTTPClient = http.DefaultClient

// Seal is the server's acceptance of one chain digest.
type Seal struct {
	Digest    string `json:"digest"`
	KeyID     string `json:"key_id"`
	Accepted  bool   `json:"accepted"`
	Integrity string `json:"integrity"`
}

// SealReport signs the report digest with a one-time key, registers the public
// key, uploads the envelope, and discards the private key. Tamper-evidence
// exists only after the SaaS accepts the seal.
func SealReport(ctx context.Context, cfg *config.Config, report *Report) (*Seal, error) {
	if cfg == nil || !cfg.SyncEnabled || strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("a SaaS seal requires a repository API key; the local chain remains a checksum")
	}
	if report.Entries == nil {
		report.Entries = []Entry{}
	}
	raw, err := json.Marshal(struct {
		Schema                   string              `json:"schema"`
		Base                     string              `json:"base"`
		Head                     string              `json:"head"`
		Entries                  []Entry             `json:"entries"`
		ConfigurationAttestation *attestation.Report `json:"configuration_attestation,omitempty"`
	}{ProtocolVersion, report.Base, report.Head, report.Entries, report.ConfigurationAttestation})
	if err != nil {
		return nil, err
	}
	payload, err := changereceipt.Canonical(raw)
	if err != nil {
		return nil, err
	}
	remote, err := changereceipt.Git(report.Repository, "remote", "get-url", "origin")
	if err != nil {
		return nil, err
	}
	name, err := changereceipt.GitHubName(remote)
	if err != nil {
		return nil, err
	}
	provider, registration, err := changereceipt.PrepareSigningKey(ctx, cfg, name, io.Discard, HTTPClient)
	if err != nil {
		return nil, err
	}
	defer provider.Close()
	signature, err := provider.Sign(append([]byte(ProtocolVersion+"\n"), payload...))
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{
		"payload":    string(payload),
		"signature":  base64.StdEncoding.EncodeToString(signature),
		"public_key": base64.StdEncoding.EncodeToString(provider.PublicKey()),
		"key_id":     registration.KeyID,
	})
	if err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(cfg.APIURL)
	if err != nil || endpoint.Scheme != "https" {
		return nil, fmt.Errorf("seal upload requires HTTPS")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + sealsPath
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(cfg.APIKey))
	request.Header.Set("Content-Type", "application/json")
	client := *HTTPClient
	client.Timeout = 8 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("seal upload failed; the local chain remains a checksum: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("seal was not accepted (HTTP %d); the local chain remains a checksum", response.StatusCode)
	}
	if !ed25519.Verify(provider.PublicKey(), append([]byte(ProtocolVersion+"\n"), payload...), signature) {
		return nil, fmt.Errorf("local seal signature failed before discard")
	}
	sum := sha256.Sum256(payload)
	return &Seal{Digest: fmt.Sprintf("sha256:%x", sum[:]), KeyID: registration.KeyID, Accepted: true, Integrity: "saas-seal"}, nil
}
