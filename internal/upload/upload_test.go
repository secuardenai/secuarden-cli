package upload

import (
	"io"
	"os/exec"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func TestSyncRequestPreservesAuthenticationAndIdempotency(t *testing.T) {
	req, err := newSyncRequest(&config.Config{APIURL: "https://api.example.invalid", APIKey: "secret"}, "stable-key", []byte(`{"session_id":"s"}`))
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.String() != "https://api.example.invalid/api/agent-ledger/session-sync" {
		t.Fatalf("url=%s", req.URL)
	}
	if req.Header.Get("Authorization") != "Bearer secret" || req.Header.Get("Idempotency-Key") != "stable-key" || req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers=%v", req.Header)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"session_id":"s"}` {
		t.Fatalf("body=%s", body)
	}
}

func TestSyncSessionNeverUsesLegacyOrOtherRepositoryCredentials(t *testing.T) {
	repo := t.TempDir()
	if out, err := exec.Command("git", "init", "--quiet", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	cfg := &config.Config{SyncEnabled: true, APIKey: "legacy-key", APIURL: "https://example.invalid"}
	if _, err := config.ConfigureIntegration(cfg, t.TempDir(), "other-key", ""); err == nil {
		t.Fatal("accepted non-repository")
	}
	if _, err := SyncSession(cfg, &storage.SessionSummary{WorkingDirectory: repo}); err == nil {
		t.Fatal("unconfigured repository used global key")
	}
	if _, err := SyncSession(cfg, &storage.SessionSummary{}); err == nil {
		t.Fatal("missing session repository used cwd")
	}
}
