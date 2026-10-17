package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/secuardenai/secuarden-cli/internal/events"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func checkpointGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, b)
	}
	return strings.TrimSpace(string(b))
}
func checkpointWrite(t *testing.T, dir, path, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
func checkpointHook(t *testing.T, dir, phase, invocation, path string) {
	t.Helper()
	payload := map[string]interface{}{"session_id": "checkpoint-session", "cwd": dir}
	if invocation != "" {
		payload["tool_use_id"] = invocation
		payload["tool_name"] = "Edit"
		payload["tool_input"] = map[string]string{"file_path": filepath.Join(dir, path)}
		payload["tool_response"] = map[string]interface{}{"success": true}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "hook.json")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	replayHookFixture(t, phase, input)
}
func checkpointFile(t *testing.T, c *repository.Checkpoint, path string) repository.FileState {
	t.Helper()
	if c == nil {
		t.Fatal("missing checkpoint")
	}
	for _, f := range c.Files {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("missing file %s", path)
	return repository.FileState{}
}
func TestDirtyRepositoryCheckpointAttribution(t *testing.T) {
	for _, mode := range []string{"redacted_content", "metadata_only"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			mustSavePrivacy(t, mode)
			dir := t.TempDir()
			checkpointGit(t, dir, "init")
			checkpointGit(t, dir, "config", "user.email", "fixture@example.com")
			checkpointGit(t, dir, "config", "user.name", "Fixture")
			for _, path := range []string{"dirty.txt", "staged.txt", "human.txt", "delete.txt"} {
				checkpointWrite(t, dir, path, "committed\n")
			}
			checkpointWrite(t, dir, ".gitignore", "ignored.txt\n")
			checkpointGit(t, dir, "add", ".")
			checkpointGit(t, dir, "commit", "-m", "baseline")
			checkpointWrite(t, dir, "dirty.txt", "pre-existing edit\n")
			checkpointWrite(t, dir, "staged.txt", "staged edit\n")
			checkpointGit(t, dir, "add", "staged.txt")
			checkpointWrite(t, dir, "staged.txt", "unstaged on staged\n")
			checkpointWrite(t, dir, "new.txt", "pre-existing untracked\n")
			checkpointWrite(t, dir, ".env", "PRIVATE_CHECKPOINT_MARKER\n")
			checkpointWrite(t, dir, "ignored.txt", "ignored\n")
			checkpointHook(t, dir, "session-start", "", "")
			db := openCaptureDB(t)
			defer db.Close()
			start, err := db.ReadSessionEnvelope("checkpoint-session")
			if err != nil {
				t.Fatal(err)
			}
			baseline := start.Events[0].RepositoryCheckpoint
			if baseline.Status != "complete" || baseline.Head != checkpointGit(t, dir, "rev-parse", "HEAD") || baseline.Tree != checkpointGit(t, dir, "rev-parse", "HEAD^{tree}") || baseline.Branch == "" || baseline.Repository == "" {
				t.Fatalf("bad baseline: %+v", baseline)
			}
			for _, path := range []string{"dirty.txt", "staged.txt", "new.txt"} {
				f := checkpointFile(t, baseline, path)
				if !f.PreExisting || f.Attribution != "pre_existing" {
					t.Fatalf("preexisting: %+v", f)
				}
			}
			staged := checkpointFile(t, baseline, "staged.txt")
			if staged.Staged != "M" || staged.Unstaged != "M" || staged.Index == "" {
				t.Fatalf("index/working state lost: %+v", staged)
			}
			for _, f := range baseline.Files {
				if f.Path == "ignored.txt" {
					t.Fatal("ignored file captured")
				}
			}
			investigation, err := db.GetSessionInvestigation("checkpoint-session")
			if err != nil {
				t.Fatal(err)
			}
			if investigation.EndCheckpointStatus != "absent" {
				t.Fatal("missing end not reported")
			}
			checkpointWrite(t, dir, "human.txt", "human between tools\n")
			checkpointHook(t, dir, "pre-tool-use", "edit-1", "dirty.txt")
			checkpointWrite(t, dir, "dirty.txt", "pre-existing edit\nagent addition\n")
			checkpointHook(t, dir, "post-tool-use", "edit-1", "dirty.txt")
			// A successful no-op on an already dirty file must not claim its bytes.
			checkpointHook(t, dir, "pre-tool-use", "edit-2", "staged.txt")
			checkpointHook(t, dir, "post-tool-use", "edit-2", "staged.txt")
			if err := os.Remove(filepath.Join(dir, "delete.txt")); err != nil {
				t.Fatal(err)
			}
			checkpointHook(t, dir, "session-end", "", "")
			envelope, err := db.ReadSessionEnvelope("checkpoint-session")
			if err != nil {
				t.Fatal(err)
			}
			final := envelope.Events[len(envelope.Events)-1].RepositoryCheckpoint
			edited := checkpointFile(t, final, "dirty.txt")
			if edited.Attribution != "agent_associated" || !edited.PreExisting || edited.BeforeDigest != fmt.Sprintf("%x", sha256.Sum256([]byte("pre-existing edit\n"))) || edited.Digest != fmt.Sprintf("%x", sha256.Sum256([]byte("pre-existing edit\nagent addition\n"))) {
				t.Fatalf("delta attribution: %+v", edited)
			}
			if f := checkpointFile(t, final, "staged.txt"); f.Attribution != "pre_existing" {
				t.Fatalf("no-op attributed dirty bytes: %+v", f)
			}
			if f := checkpointFile(t, final, "human.txt"); f.Attribution != "human_or_unattributed" {
				t.Fatalf("human edit misattributed: %+v", f)
			}
			if f := checkpointFile(t, final, "delete.txt"); f.Status != "deleted" || f.Digest != "" || f.Attribution != "human_or_unattributed" {
				t.Fatalf("deletion: %+v", f)
			}
			sensitive := checkpointFile(t, final, ".env")
			if !sensitive.Sensitive || sensitive.Digest == "" {
				t.Fatalf("sensitive path policy: %+v", sensitive)
			}
			// Validate the emitted checkpoint-bearing event against the public contract.
			schemaBytes, err := os.ReadFile("../../schema/stage1/v2/event.schema.json")
			if err != nil {
				t.Fatal(err)
			}
			schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
			if err != nil {
				t.Fatal(err)
			}
			compiler := jsonschema.NewCompiler()
			if err := compiler.AddResource(events.SchemaURL, schemaDoc); err != nil {
				t.Fatal(err)
			}
			schema, err := compiler.Compile(events.SchemaURL)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range envelope.Events {
				encoded, _ := json.Marshal(e)
				doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
				if err != nil {
					t.Fatal(err)
				}
				if err := schema.Validate(doc); err != nil {
					t.Fatalf("checkpoint schema: %v", err)
				}
			}
			data, _ := json.Marshal(envelope)
			if strings.Contains(string(data), "PRIVATE_CHECKPOINT_MARKER") {
				t.Fatal("sensitive contents leaked")
			}
			for _, e := range envelope.Events {
				c := e.RepositoryCheckpoint
				start, err := time.Parse(time.RFC3339Nano, c.StartedAt)
				if err != nil {
					t.Fatal(err)
				}
				end, err := time.Parse(time.RFC3339Nano, c.FinishedAt)
				if err != nil || end.Before(start) {
					t.Fatal("invalid checkpoint interval")
				}
				for _, f := range c.Files {
					at, err := time.Parse(time.RFC3339Nano, f.ObservedAt)
					if err != nil || at.Before(start) || at.After(end) {
						t.Fatalf("invalid observation time: %+v", f)
					}
				}
			}
			result, err := db.VerifyIntegrity()
			if err != nil || !result.Valid {
				t.Fatalf("integrity: %+v %v", result, err)
			}
			investigation, err = db.GetSessionInvestigation("checkpoint-session")
			if err != nil {
				t.Fatal(err)
			}
			if investigation.BaselineStatus != "complete" || investigation.EndCheckpointStatus != "complete" || len(investigation.RepositoryCheckpoints) != 6 {
				t.Fatalf("checkpoint reporting: %+v", investigation)
			}
			captured, err := db.QueryEvents(storage.EventFilter{SessionID: "checkpoint-session", Limit: 10})
			if err != nil || captured[0].RepositoryCheckpoint == nil {
				t.Fatal("checkpoint omitted from event query")
			}
		})
	}
}

func TestCheckpointMissingBaselineAndFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	mustSavePrivacy(t, "metadata_only")
	dir := t.TempDir()
	checkpointHook(t, dir, "post-tool-use", "orphan", "file.txt")
	db := openCaptureDB(t)
	defer db.Close()
	env, err := db.ReadSessionEnvelope("checkpoint-session")
	if err != nil {
		t.Fatal(err)
	}
	c := env.Events[0].RepositoryCheckpoint
	if c.Status != "failed" || !containsString(c.Reasons, "repository_unavailable") || !containsString(c.Reasons, "baseline_absent") || !containsString(c.Reasons, "pre_checkpoint_absent") {
		t.Fatalf("missing failure evidence: %+v", c)
	}
	if env.Events[0].Completeness.State != "partial" {
		t.Fatal("failure reported complete")
	}
}
