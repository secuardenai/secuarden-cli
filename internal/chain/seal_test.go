package chain

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/changereceipt"
	"github.com/secuardenai/secuarden-cli/internal/config"
)

func TestSealAcceptedByServer(t *testing.T) {
	var public ed25519.PublicKey
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case changereceipt.SigningKeysPath:
			var request struct {
				PublicKey string `json:"public_key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(request.PublicKey)
			if err != nil || len(decoded) != 32 {
				t.Errorf("public key: %v", err)
			}
			public = decoded
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(changereceipt.Registration{
				KeyID: changereceipt.KeyID(public), TenantID: "tenant-1",
				Repository:   changereceipt.Repository{Provider: "github", ID: "123", FullName: "owner/repo"},
				RegisteredAt: "2026-10-08T00:00:00Z",
			})
		case sealsPath:
			var envelope map[string]string
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				t.Error(err)
			}
			signature, err := base64.StdEncoding.Strict().DecodeString(envelope["signature"])
			if err != nil || !ed25519.Verify(public, append([]byte(ProtocolVersion+"\n"), []byte(envelope["payload"])...), signature) {
				t.Errorf("seal signature did not verify")
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	previous := HTTPClient
	HTTPClient = server.Client()
	defer func() { HTTPClient = previous }()

	root := t.TempDir()
	gitCmd(t, root, "init", "-q", "-b", "main")
	gitCmd(t, root, "remote", "add", "origin", "https://github.com/owner/repo.git")
	report := &Report{Repository: root, Base: "abc", Head: "def", Integrity: "checksum"}
	seal, err := SealReport(context.Background(), &config.Config{SyncEnabled: true, APIKey: "test-secret", APIURL: server.URL}, report)
	if err != nil {
		t.Fatal(err)
	}
	if !seal.Accepted || seal.Integrity != "saas-seal" || seal.KeyID == "" {
		t.Fatalf("seal = %#v", seal)
	}
}
