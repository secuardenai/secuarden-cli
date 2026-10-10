package changereceipt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/config"
)

func TestRegistration(t *testing.T) {
	for _, scenario := range []string{"success", "unauthorized", "missing-endpoint", "wrong-key", "missing-tenant", "wrong-repo", "wrong-provider", "bad-id", "bad-time", "bad-json", "oversized", "redirect"} {
		t.Run(scenario, func(t *testing.T) {
			var public ed25519.PublicKey
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != SigningKeysPath || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer test-secret" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("wrong authenticated request")
				}
				var request map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				if len(request) != 3 || string(request["algorithm"]) != `"Ed25519"` {
					t.Error("unexpected request fields")
				}
				var encoded string
				_ = json.Unmarshal(request["public_key"], &encoded)
				decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
				if err != nil || len(decoded) != 32 {
					t.Error("not a raw public key")
				}
				public = ed25519.PublicKey(decoded)
				var repo map[string]string
				_ = json.Unmarshal(request["repository"], &repo)
				if len(repo) != 2 || repo["provider"] != "github" || repo["full_name"] != "owner/repo" {
					t.Error("unexpected repository request")
				}
				response := Registration{KeyID(public), "tenant-1", Repository{"github", "123", "owner/repo"}, "2026-10-08T00:00:00Z"}
				switch scenario {
				case "unauthorized":
					w.WriteHeader(401)
					fmt.Fprint(w, "test-secret")
					return
				case "missing-endpoint":
					w.WriteHeader(404)
					return
				case "redirect":
					w.Header().Set("Location", "/redirected")
					w.WriteHeader(307)
					return
				case "wrong-key":
					response.KeyID = "wrong"
				case "missing-tenant":
					response.TenantID = ""
				case "wrong-repo":
					response.Repository.FullName = "other/repo"
				case "wrong-provider":
					response.Repository.Provider = "gitlab"
				case "bad-id":
					response.Repository.ID = "1e3"
				case "bad-time":
					response.RegisteredAt = "yesterday"
				case "bad-json":
					fmt.Fprint(w, "not-json test-secret")
					return
				case "oversized":
					fmt.Fprint(w, strings.Repeat("x", 65537))
					return
				}
				w.WriteHeader(201)
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			var logs bytes.Buffer
			p, registration, err := PrepareSigningKey(context.Background(), &config.Config{SyncEnabled: true, APIKey: "test-secret", APIURL: server.URL}, "owner/repo", &logs, server.Client())
			if calls != 1 {
				t.Fatalf("unexpected calls: %d", calls)
			}
			if scenario == "success" {
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				if registration.KeyID != KeyID(public) || !bytes.Equal(p.PublicKey(), public) {
					t.Fatal("registered different key")
				}
				if !strings.Contains(logs.String(), "Public key pushed to Secuarden") {
					t.Fatal("missing success log")
				}
			} else {
				if err == nil || p != nil || registration != nil {
					t.Fatal("failure accepted")
				}
				if strings.Contains(logs.String(), "Public key pushed") || strings.Contains(err.Error(), "test-secret") {
					t.Fatal("unsafe error or false success")
				}
			}
			if strings.Contains(logs.String(), "test-secret") {
				t.Fatal("credential logged")
			}
		})
	}
}

func TestRegistrationPreconditions(t *testing.T) {
	for _, cfg := range []*config.Config{nil, {}, {SyncEnabled: true}, {APIKey: "secret"}, {SyncEnabled: true, APIKey: " "}, {SyncEnabled: true, APIKey: "secret", APIURL: "http://example.com"}} {
		var logs bytes.Buffer
		p, _, err := PrepareSigningKey(context.Background(), cfg, "owner/repo", &logs, nil)
		if err == nil || p != nil || logs.Len() != 0 {
			t.Fatal("generated key before prerequisites")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var logs bytes.Buffer
	p, _, err := PrepareSigningKey(ctx, &config.Config{SyncEnabled: true, APIKey: "secret", APIURL: "https://example.invalid"}, "owner/repo", &logs, nil)
	if err == nil || p != nil || strings.Contains(logs.String(), "Public key pushed") {
		t.Fatal("network failure accepted")
	}
}
