package observationcapture

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func enabled(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "capture")
	if _, err := Configure(dir, true); err != nil {
		t.Fatal(err)
	}
	return dir
}
func TestCaptureDurableBoundedAndOptIn(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "off")
	if _, err := Capture(context.Background(), dir, "Stop", "test", strings.NewReader("{}")); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("disabled capture wrote files")
	}
	dir = enabled(t)
	for _, tc := range []struct{ body, gap string }{{"not JSON", ""}, {strings.Repeat("x", MaxInputBytes+10), "oversized_input"}} {
		e, err := Capture(context.Background(), dir, "Stop", "test", strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		if e.Gap != tc.gap || len(e.Payload) > MaxInputBytes {
			t.Fatalf("invalid bounded envelope: %s %d", e.Gap, len(e.Payload))
		}
		path := filepath.Join(dir, "inbox", e.ID+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var disk Envelope
		if err = json.Unmarshal(data, &disk); err != nil {
			t.Fatal(err)
		}
		if disk.Hash != Hash(disk.Payload) || disk.ID != e.ID {
			t.Fatal("acknowledged data not reloadable")
		}
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Fatal(info.Mode())
		}
	}
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	start := time.Now()
	e, err := Capture(context.Background(), dir, "Stop", "test", r)
	if err != nil || e.Gap != "input_timeout" {
		t.Fatalf("%+v %v", e, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("stalled input did not acknowledge promptly")
	}
}
func TestCaptureConcurrentAndUnavailableInbox(t *testing.T) {
	dir := enabled(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Capture(context.Background(), dir, "Stop", "test", strings.NewReader("{}")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	entries, err := os.ReadDir(filepath.Join(dir, "inbox"))
	if err != nil || len(entries) != 20 {
		t.Fatalf("%d %v", len(entries), err)
	}
	blocked := enabled(t)
	if err := os.Rename(filepath.Join(blocked, "inbox"), filepath.Join(blocked, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "inbox"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := Capture(context.Background(), blocked, "Stop", "test", strings.NewReader("secret"))
	if err == nil || e.Gap != "inbox_unavailable" {
		t.Fatal("missing explicit capture failure")
	}
	b, err := os.ReadFile(filepath.Join(blocked+"-failures", e.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var failure Envelope
	json.Unmarshal(b, &failure)
	if len(failure.Payload) != 0 || failure.Gap != "inbox_unavailable" {
		t.Fatal("failure fallback retained input")
	}
}
func envelope(body string) Envelope {
	return Envelope{Version: Version, ID: "delivery", Epoch: "epoch", Event: "PostToolUse", ReceivedAt: time.Date(2026, 10, 4, 1, 0, 0, 0, time.UTC), Payload: []byte(body), Hash: Hash([]byte(body)), CollectorVersion: "test"}
}
func TestNormalizeIndependentEvidenceAndRejectsAmbiguity(t *testing.T) {
	valid := `{"session_id":"s","cwd":"/repo","hook_event_name":"PostToolUse","tool_use_id":"call","tool_name":"apply_patch","tool_input":{"input":"*** Update File: x.go\n+private content"},"tool_response":{"exit_code":0},"timestamp":"2026-10-04T00:00:00Z","codex_version":"1"}`
	o, err := Normalize(envelope(valid))
	if err != nil {
		t.Fatal(err)
	}
	if o.Outcome != "success" || len(o.Paths) != 1 || o.Paths[0] != "x.go" || o.SourceVersion != "1" || !strings.Contains(strings.Join(o.Gaps, ","), "delayed_input") {
		t.Fatalf("%+v", o)
	}
	b, _ := json.Marshal(o)
	if strings.Contains(string(b), "private content") {
		t.Fatal("raw content retained in normalized observation")
	}
	for _, body := range []string{`{`, `[]`, `{"session_id":"a","session_id":"b"}`, strings.Replace(valid, `"/repo"`, `"relative"`, 1), valid + `{}`} {
		if _, err := Normalize(envelope(body)); err == nil {
			t.Errorf("accepted malformed %s", body)
		}
	}
	var object map[string]interface{}
	json.Unmarshal([]byte(valid), &object)
	pretty, _ := json.MarshalIndent(object, "", " ")
	same, err := Normalize(envelope(string(pretty)))
	if err != nil || same.ID != o.ID {
		t.Fatal("canonical duplicates differ")
	}
	conflict, err := Normalize(envelope(strings.Replace(valid, `"exit_code":0`, `"exit_code":1`, 1)))
	if err != nil || conflict.ID == o.ID || conflict.LogicalID != o.LogicalID {
		t.Fatal("conflict identity lost")
	}
	missing, err := Normalize(envelope(strings.Replace(valid, `,"timestamp":"2026-10-04T00:00:00Z"`, "", 1)))
	if err != nil || missing.TimeBasis != "receipt" {
		t.Fatal("missing source time fabricated")
	}
}
func TestHookMergeCoexistsAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	legacy := `{"other":{"preserve":true},"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"secuarden hook codex-post-tool-use"}]}]}}`
	os.WriteFile(path, []byte(legacy), 0600)
	fragment, err := HookDefinitions("/tmp/binary with spaces/secuarden", "/tmp/inbox's path")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := MergeHooks(path, fragment); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(path)
	if strings.Count(string(b), "secuarden hook codex-post-tool-use") != 1 || strings.Count(string(b), "observe-codex") != len(HookEvents) || !strings.Contains(string(b), "preserve") {
		t.Fatalf("merge damaged registrations: %s", b)
	}
}
