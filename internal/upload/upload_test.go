package upload

import (
	"io"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/config"
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
