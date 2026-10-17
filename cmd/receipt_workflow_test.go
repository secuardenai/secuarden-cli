package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/changeledger"
	"github.com/secuardenai/secuarden-cli/internal/changereceipt"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/spf13/cobra"
)

func receiptRepo(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	git := func(args ...string) string {
		out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %s %v", args, out, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("config", "user.name", "Test")
	git("config", "user.email", "test@example.com")
	git("remote", "add", "origin", "git@github.com:owner/repo.git")
	os.WriteFile(filepath.Join(root, "a"), []byte("base"), 0600)
	git("add", ".")
	git("commit", "-qm", "base")
	base := git("rev-parse", "HEAD")
	git("branch", "receipt-target")
	os.WriteFile(filepath.Join(root, "a"), []byte("head"), 0600)
	git("commit", "-qam", "head")
	head := git("rev-parse", "HEAD")
	canonical, _ := filepath.EvalSymlinks(root)
	return canonical, base, head
}
func TestReceiptAutomaticEndToEndAndFailOpen(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root, _, head := receiptRepo(t)
	oldDB := ledgerDB
	ledgerDB = filepath.Join(t.TempDir(), "ledger.db")
	defer func() { ledgerDB = oldDB }()
	var uploads int
	publics := map[string]string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("missing auth")
		}
		switch r.URL.Path {
		case changereceipt.SigningKeysPath:
			var req struct {
				PublicKey string `json:"public_key"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			public, _ := base64.StdEncoding.DecodeString(req.PublicKey)
			key := changereceipt.KeyID(ed25519.PublicKey(public))
			publics[key] = req.PublicKey
			json.NewEncoder(w).Encode(changereceipt.Registration{KeyID: key, TenantID: "tenant", Repository: changereceipt.Repository{Provider: "github", ID: "123", FullName: "owner/repo"}, RegisteredAt: "2026-10-10T00:00:00Z"})
		case changereceipt.ReceiptsPath:
			uploads++
			var e changereceipt.Envelope
			json.NewDecoder(r.Body).Decode(&e)
			var p changereceipt.Payload
			json.Unmarshal(e.Payload, &p)
			public, _ := base64.StdEncoding.DecodeString(publics[p.KeyID])
			sig, _ := base64.StdEncoding.DecodeString(e.Signature)
			if !ed25519.Verify(public, append([]byte(changereceipt.ProtocolVersion+"\n"), e.Payload...), sig) {
				t.Error("signature invalid")
			}
			json.NewEncoder(w).Encode(changereceipt.UploadAcknowledgement{ReceiptID: p.ReceiptID, ReceiptIntegrity: "verified", EvidenceIntegrity: "verified", RevisionMatch: "pending", CoverageState: "unobserved", ReceivedAt: "2026-10-10T00:00:00Z", InspectionURL: "https://" + r.Host + "/receipt"})
		default:
			t.Error("unexpected route")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	// Test-only trust of the local TLS server; production uses normal certificate validation.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	oldTransport := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = oldTransport; transport.CloseIdleConnections() }()
	cfg := &config.Config{RepositoryIntegrations: map[string]config.Integration{root: {SyncEnabled: true, APIKey: "test-key", APIURL: server.URL, Receipt: config.ReceiptOptions{Mode: "automatic", BaseRef: "receipt-target"}}}}
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	receipt := &cobra.Command{Use: "receipt"}
	addReceiptWorkflow(receipt)
	var output bytes.Buffer
	receipt.SetOut(&output)
	receipt.SetErr(&output)
	zero := strings.Repeat("0", 40)
	input := "refs/heads/a " + head + " refs/heads/a " + zero + "\nrefs/heads/b " + head + " refs/heads/b " + zero + "\n"
	receipt.SetIn(strings.NewReader(input))
	receipt.SetArgs([]string{"pre-push", "--repo", root, "--", "origin", "git@github.com:owner/repo.git"})
	if err := receipt.Execute(); err != nil {
		t.Fatal(err)
	}
	if uploads != 2 {
		t.Fatalf("uploads %d: %s", uploads, &output)
	}
	store, err := changeledger.Open(ledgerDB)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	status, err := store.LatestReceiptOutcome(root)
	if err != nil || !strings.Contains(status, "uploaded") {
		t.Fatalf("status: %s %v", status, err)
	}
	// Malformed capture input does not reject Git's push.
	receipt.SetIn(strings.NewReader("malformed\n"))
	receipt.SetArgs([]string{"pre-push", "--repo", root, "--", "origin", "git@github.com:owner/repo.git"})
	if err = receipt.Execute(); err != nil {
		t.Fatalf("capture blocked push: %v", err)
	}
	// An unrelated original hook still rejects the push.
	original := filepath.Join(t.TempDir(), "pre-push")
	os.WriteFile(original, []byte("#!/bin/sh\ncat >/dev/null\nexit 7\n"), 0700)
	receipt.SetIn(strings.NewReader(input))
	receipt.SetArgs([]string{"pre-push", "--repo", root, "--original", original, "--", "origin", "git@github.com:owner/repo.git"})
	if err = receipt.Execute(); err == nil {
		t.Fatal("original rejection suppressed")
	}

}
