package changereceipt

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
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/changeledger"
	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/observationcapture"
)

func gitTest(t *testing.T, root string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %s %v", args, out, err)
	}
	return strings.TrimSpace(string(out))
}
func artifactTest(t *testing.T) *Artifact {
	t.Helper()
	root := t.TempDir()
	gitTest(t, root, "init", "-q")
	gitTest(t, root, "config", "user.name", "Test")
	gitTest(t, root, "config", "user.email", "test@example.com")
	gitTest(t, root, "remote", "add", "origin", "git@github.com:owner/repo.git")
	os.WriteFile(filepath.Join(root, "file"), []byte("base"), 0600)
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-qm", "base")
	base := gitTest(t, root, "rev-parse", "HEAD")
	os.WriteFile(filepath.Join(root, "file"), []byte("head"), 0600)
	gitTest(t, root, "commit", "-qam", "head")
	c, err := changeledger.Build(changeledger.BuildOptions{Repository: root, Base: base})
	if err != nil {
		t.Fatal(err)
	}
	store, err := changeledger.Open(filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = store.Put(c); err != nil {
		t.Fatal(err)
	}
	coverage, obs, cps, err := store.ReceiptSnapshot(c.Digest)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewEphemeralProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	reg := Registration{KeyID(p.PublicKey()), "tenant", Repository{"github", "123", "owner/repo"}, "2026-10-10T00:00:00Z"}
	a, err := NewArtifact(p, &reg, Evidence{Change: c, Scopes: coverage.Scopes, Observations: obs, Checkpoints: cps, Links: coverage.Links, Coverage: coverage, Sources: map[string]string{"cli_version": "test"}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestCanonicalValidation(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"n":9007199254740992}`, `{"n":1e400}`, `{"s":"\ud800"}`, `{} {}`, string([]byte{'"', 255, '"'})} {
		if _, err := Canonical([]byte(raw)); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	got, err := Canonical([]byte(`{"z":1.0,"a":"é","n":1e-7}`))
	if err != nil || string(got) != `{"a":"é","n":1e-7,"z":1}` {
		t.Fatalf("JCS: %s %v", got, err)
	}
}
func TestArtifactTamperingAndFreshProcessUpload(t *testing.T) {
	a := artifactTest(t)
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"payload", "evidence", "key", "signature"} {
		var copy Artifact
		json.Unmarshal(raw, &copy)
		switch field {
		case "payload":
			copy.Envelope.Payload = bytes.Replace(copy.Envelope.Payload, []byte(`"tenant"`), []byte(`"other"`), 1)
		case "evidence":
			copy.Envelope.Evidence = bytes.Replace(copy.Envelope.Evidence, []byte(`"unobserved"`), []byte(`"complete"`), 1)
		case "key":
			copy.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
		case "signature":
			copy.Envelope.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
		}
		if copy.Verify() == nil {
			t.Errorf("accepted tampered %s", field)
		}
	}
	path := filepath.Join(t.TempDir(), "ledger.db")
	store, err := changeledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id := a.Payload().ReceiptID
	if err = store.SaveSignedReceipt(id, "/test", raw); err != nil {
		t.Fatal(err)
	}
	store.Close()
	store, err = changeledger.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record, err := store.SignedReceipt(id)
	if err != nil {
		t.Fatal(err)
	}
	raw = record.Artifact
	// Serialization contains only the public key and signed bytes; provider has already closed.
	if bytes.Contains(raw, []byte("private")) {
		t.Fatal("private material serialized")
	}
	var restored Artifact
	if err = json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if err = restored.Verify(); err != nil {
		t.Fatal(err)
	}
}
func TestUploadRetryBytesAndTerminalErrors(t *testing.T) {
	a := artifactTest(t)
	for _, scenario := range []string{"retry", "unauthorized", "conflict", "bad-ack", "redirect"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			var first []byte
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				body, _ := io.ReadAll(r.Body)
				if calls == 1 {
					first = body
				} else if !bytes.Equal(first, body) {
					t.Error("retry changed signed bytes")
				}
				if r.URL.Path != ReceiptsPath || r.Header.Get("Authorization") != "Bearer secret" {
					t.Error("bad request")
				}
				switch scenario {
				case "retry":
					if calls == 1 {
						w.WriteHeader(503)
						return
					}
				case "unauthorized":
					w.WriteHeader(401)
					return
				case "conflict":
					w.WriteHeader(409)
					return
				case "redirect":
					w.Header().Set("Location", "/other")
					w.WriteHeader(307)
					return
				case "bad-ack":
					fmt.Fprint(w, `{"receipt_id":"wrong"}`)
					return
				}
				json.NewEncoder(w).Encode(UploadAcknowledgement{a.Payload().ReceiptID, "verified", "verified", "pending", "unobserved", "2026-10-10T00:00:00Z", "https://" + r.Host + "/receipt"})
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := Upload(ctx, &config.Config{SyncEnabled: true, APIKey: "secret", APIURL: server.URL}, a, server.Client())
			if scenario == "retry" {
				if err != nil || calls != 2 {
					t.Fatalf("retry: %v calls %d", err, calls)
				}
			} else if err == nil || calls != 1 {
				t.Fatalf("terminal error: %v calls %d", err, calls)
			}
		})
	}
}
func TestParsePushUpdates(t *testing.T) {
	oid := strings.Repeat("a", 40)
	zero := strings.Repeat("0", 40)
	input := "refs/heads/a " + oid + " refs/heads/a " + zero + "\n(delete) " + zero + " refs/heads/b " + oid + "\n"
	updates, err := ParseUpdates(strings.NewReader(input))
	if err != nil || len(updates) != 2 {
		t.Fatal(updates, err)
	}
	if _, err := ParseUpdates(strings.NewReader("bad input")); err == nil {
		t.Fatal("invalid accepted")
	}
}
func TestHookInstallPreservesAndRestores(t *testing.T) {
	root := t.TempDir()
	gitTest(t, root, "init", "-q")
	path, err := HookPath(root)
	if err != nil {
		t.Fatal(err)
	}
	original := []byte("#!/bin/sh\nexit 7\n")
	os.WriteFile(path, original, 0700)
	if err = ConfigureHook(root, "/tmp/bin with spaces", "automatic"); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(path + ".secuarden-original")
	if !bytes.Equal(saved, original) {
		t.Fatal("original overwritten")
	}
	if err = ConfigureHook(root, "/tmp/new", "automatic"); err != nil {
		t.Fatal(err)
	}
	if err = ConfigureHook(root, "/tmp/new", "explicit"); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(path)
	if !bytes.Equal(restored, original) {
		t.Fatal("original not restored")
	}
	gitTest(t, root, "config", "core.hooksPath", "/tmp/shared")
	if ConfigureHook(root, "/tmp/new", "automatic") == nil {
		t.Fatal("shared hooks overwritten")
	}
}

// Cross-language fixture generation uses a test-only fixed seed, never production entropy.
type fixtureProvider struct{ private ed25519.PrivateKey }

func (p fixtureProvider) PublicKey() ed25519.PublicKey { return p.private.Public().(ed25519.PublicKey) }
func (p fixtureProvider) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(p.private, message), nil
}
func TestSharedFixture(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	provider := fixtureProvider{ed25519.NewKeyFromSeed(seed)}
	paths := []changeledger.ChangedPath{{Status: "M", Path: "src/é<&>.go"}}
	c := &changeledger.Change{Version: changeledger.ContractVersion, Status: "complete", Repository: "github.com/owner/repo", BaseCommit: strings.Repeat("1", 40), BaseTree: strings.Repeat("2", 40), HeadCommit: strings.Repeat("3", 40), HeadTree: strings.Repeat("4", 40), ChangedPaths: paths, Observations: []changeledger.Observation{}, InferredLinks: []changeledger.InferredLink{}, CaptureGaps: []changeledger.CaptureGap{}}
	projection := struct {
		Version, Repository, BaseCommit, BaseTree, HeadCommit, HeadTree string
		ChangedPaths                                                    []struct {
			Status  string `json:"status"`
			Path    string `json:"path"`
			OldPath string `json:"old_path,omitempty"`
		}
	}{c.Version, c.Repository, c.BaseCommit, c.BaseTree, c.HeadCommit, c.HeadTree, []struct {
		Status  string `json:"status"`
		Path    string `json:"path"`
		OldPath string `json:"old_path,omitempty"`
	}{{"M", "src/é<&>.go", ""}}}
	projectionBytes, _ := json.Marshal(projection)
	c.Digest = fmt.Sprintf("sha256:%x", sha256.Sum256(projectionBytes))
	stamp := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	scopes := []changeledger.ObservationScope{{SessionID: "session-a", Since: stamp, Until: stamp.Add(time.Hour)}, {SessionID: "session-b", Since: stamp, Until: stamp.Add(time.Hour)}}
	coverage := &changeledger.Coverage{Version: changeledger.ContractVersion, ChangeDigest: c.Digest, State: "unobserved", Scopes: scopes, Links: []changeledger.ObservationLink{}, Reasons: []changeledger.CoverageGap{{Version: changeledger.ContractVersion, Code: "no_matching_observations", Source: "test-fixture", SourceVersion: "v1", ObservedAt: stamp, Detail: "No attributable observations captured."}}}
	reg := Registration{KeyID(provider.PublicKey()), "tenant-fixture", Repository{"github", "123", "owner/repo"}, "2026-10-10T00:00:00Z"}
	evidence := Evidence{SnapshotAt: "2026-10-10T00:00:00Z", Change: c, Scopes: scopes, Observations: []observationcapture.Observation{}, Checkpoints: []changeledger.ObservationCheckpoint{}, Links: []changeledger.ObservationLink{}, Coverage: coverage, Sources: map[string]string{"cli_version": "fixture", "normalizer_version": observationcapture.Version, "attribution_version": observationcapture.Version}}
	a, err := NewArtifact(provider, &reg, evidence)
	if err != nil {
		t.Fatal(err)
	}
	payload := a.Payload()
	payload.ReceiptID = "00000000-0000-4000-8000-000000000001"
	payload.IssuedAt = "2026-10-10T00:00:00Z"
	a.Envelope.Payload, err = canonicalObject(payload)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte(ProtocolVersion+"\n"), a.Envelope.Payload...)
	a.Envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(provider.private, message))
	if err = a.Verify(); err != nil {
		t.Fatal(err)
	}
	fixture := struct {
		Seed             string    `json:"test_only_seed_base64"`
		Artifact         *Artifact `json:"artifact"`
		PayloadBytes     string    `json:"canonical_payload_utf8"`
		EvidenceBytes    string    `json:"canonical_evidence_utf8"`
		Message          string    `json:"signed_message_base64"`
		ChangeProjection string    `json:"change_projection_utf8"`
	}{base64.StdEncoding.EncodeToString(seed), a, string(a.Envelope.Payload), string(a.Envelope.Evidence), base64.StdEncoding.EncodeToString(message), string(projectionBytes)}
	raw, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "receipt-v1.json")
	if os.Getenv("UPDATE_RECEIPT_FIXTURES") == "1" {
		os.MkdirAll("testdata", 0700)
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, expected) {
		t.Fatal("shared receipt fixture changed")
	}
}

func TestRetryExhaustionAndBudget(t *testing.T) {
	a := artifactTest(t)
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) }))
	defer server.Close()
	cfg := &config.Config{SyncEnabled: true, APIKey: "secret", APIURL: server.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := Upload(ctx, cfg, a, server.Client()); err == nil || calls != 5 {
		t.Fatalf("exhaustion: calls %d, %v", calls, err)
	}
	calls = 0
	short, cancelShort := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelShort()
	if _, err := Upload(short, cfg, a, server.Client()); err == nil || calls != 1 {
		t.Fatalf("budget: calls %d, %v", calls, err)
	}
}
