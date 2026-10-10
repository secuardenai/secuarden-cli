package repository

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCheckpointDoesNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %v %s", err, b)
		}
	}
	git("init")
	git("config", "user.email", "test@example.com")
	git("config", "user.name", "Test")
	path := filepath.Join(dir, "normal.txt")
	if err := os.WriteFile(path, []byte("normal"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-m", "initial")
	outside := filepath.Join(t.TempDir(), "private.txt")
	if err := os.WriteFile(outside, []byte("outside secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	c := CaptureCheckpoint(dir, "session_end")
	if c.Status != "partial" {
		t.Fatalf("omission not reported: %+v", c)
	}
	for _, f := range c.Files {
		if f.Path == "link.txt" {
			if f.Digest != "" || f.Status != "omitted_nonregular" {
				t.Fatalf("followed symlink: %+v", f)
			}
			return
		}
	}
	t.Fatal("symlink omission absent")
}

func TestUnbornCheckpointIsExplicitlyPartial(t *testing.T) {
	dir := t.TempDir()
	if b, err := exec.Command("git", "-C", dir, "init").CombinedOutput(); err != nil {
		t.Fatalf("git: %v %s", err, b)
	}
	c := CaptureCheckpoint(dir, "session_start")
	if c.Status != "partial" || c.Head != "" || c.Tree != "" || len(c.Reasons) == 0 || c.FinishedAt == "" {
		t.Fatalf("unborn repository: %+v", c)
	}
}

func TestCheckpointSensitiveParentPolicy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".ssh", "repo")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("git", "-C", dir, "init").CombinedOutput(); err != nil {
		t.Fatalf("git: %v %s", err, b)
	}
	if err := os.WriteFile(filepath.Join(dir, "ordinary.txt"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	c := CaptureCheckpoint(dir, "session_start")
	if len(c.Files) != 1 || !c.Files[0].Sensitive || c.Files[0].Digest == "" {
		t.Fatalf("sensitive directory policy lost: %+v", c)
	}
}
