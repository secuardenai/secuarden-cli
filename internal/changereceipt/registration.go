package changereceipt

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/config"
)

const SigningKeysPath = "/api/change-ledger/v1/signing-keys"

type Repository struct {
	Provider string `json:"provider"`
	ID       string `json:"id"`
	FullName string `json:"full_name"`
}

type Registration struct {
	KeyID        string     `json:"key_id"`
	TenantID     string     `json:"tenant_id"`
	Repository   Repository `json:"repository"`
	RegisteredAt string     `json:"registered_at"`
}

var repositoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$`)
var repositoryID = regexp.MustCompile(`^[1-9][0-9]*$`)

// PrepareSigningKey checks the existing integration configuration before
// generating a key. Ownership transfers to the caller only after registration.
// No private key is persisted, logged, or sent over the network.
func PrepareSigningKey(ctx context.Context, cfg *config.Config, fullName string, logs io.Writer, client *http.Client) (*EphemeralProvider, *Registration, error) {
	if cfg == nil || !cfg.SyncEnabled || strings.TrimSpace(cfg.APIKey) == "" {
		return nil, nil, fmt.Errorf("SaaS integration is not enabled and is REQUIRED; run `secuarden init --api-key ...`")
	}
	if !repositoryName.MatchString(fullName) || strings.HasSuffix(fullName, "/.") || strings.HasSuffix(fullName, "/..") {
		return nil, nil, fmt.Errorf("repository must be a GitHub owner/name")
	}
	u, err := url.Parse(cfg.APIURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, nil, fmt.Errorf("receipt registration requires an HTTPS api_url without credentials, query, or fragment")
	}
	if logs == nil {
		logs = io.Discard
	}
	fmt.Fprintln(logs, "Integration with Secuarden is active - generating the key pair for receipt signature.")
	provider, err := NewEphemeralProvider()
	if err != nil {
		return nil, nil, err
	}
	ok := false
	defer func() {
		if !ok {
			provider.Close()
		}
	}()
	fmt.Fprintln(logs, "Keys generated successfully.")
	public := provider.PublicKey()
	body, err := json.Marshal(struct {
		Algorithm  string `json:"algorithm"`
		PublicKey  string `json:"public_key"`
		Repository struct {
			Provider string `json:"provider"`
			FullName string `json:"full_name"`
		} `json:"repository"`
	}{"Ed25519", base64.StdEncoding.EncodeToString(public), struct {
		Provider string `json:"provider"`
		FullName string `json:"full_name"`
	}{"github", fullName}})
	if err != nil {
		return nil, nil, fmt.Errorf("encode key registration")
	}
	u.Path = strings.TrimRight(u.Path, "/") + SigningKeysPath
	u.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("build key registration request")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(cfg.APIKey))
	req.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = &http.Client{}
	}
	// Never forward credentials or public-key registration to a redirect target.
	safeClient := *client
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	safeClient.Timeout = 8 * time.Second
	resp, err := safeClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("public-key registration failed (network or TLS error); receipt creation incomplete")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, nil, fmt.Errorf("public-key registration failed (HTTP %d); receipt creation incomplete", resp.StatusCode)
	}
	const limit = 64 * 1024
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(raw) > limit {
		return nil, nil, fmt.Errorf("invalid key registration response size or read failure")
	}
	var registration Registration
	if err := json.Unmarshal(raw, &registration); err != nil {
		return nil, nil, fmt.Errorf("invalid key registration response JSON")
	}
	timestamp, err := time.Parse(time.RFC3339, registration.RegisteredAt)
	if registration.KeyID != KeyID(public) || strings.TrimSpace(registration.TenantID) == "" ||
		registration.Repository.Provider != "github" || !repositoryID.MatchString(registration.Repository.ID) ||
		!strings.EqualFold(registration.Repository.FullName, fullName) || err != nil || timestamp.IsZero() || !strings.HasSuffix(registration.RegisteredAt, "Z") {
		return nil, nil, fmt.Errorf("invalid key registration response identity or timestamp")
	}
	fmt.Fprintln(logs, "Public key pushed to Secuarden for later verification of uploaded receipts.")
	ok = true
	return provider, &registration, nil
}
