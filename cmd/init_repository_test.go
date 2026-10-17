package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestInitRejectsNonRepositoryBeforeSetup(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	previous := initRepo
	initRepo = t.TempDir()
	t.Cleanup(func() { initRepo = previous })
	err := runInit(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "per-repository setup requires a Git repository") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".secuarden")); !os.IsNotExist(err) {
		t.Fatal("setup mutated configuration before repository validation")
	}
}

func TestInitHelpDocumentsRequiredRepositorySetup(t *testing.T) {
	var output bytes.Buffer
	initCmd.SetOut(&output)
	t.Cleanup(func() { initCmd.SetOut(nil) })
	if err := initCmd.Help(); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"Per-repository setup is required", "Always pass --repo PATH explicitly", "User-wide API keys are not a fallback", "this repository only"} {
		if !strings.Contains(output.String(), text) {
			t.Fatalf("help missing %q", text)
		}
	}
}

func TestInitRequiresExplicitRepository(t *testing.T) {
	// Exercise Cobra validation in a fresh process while running inside the
	// checkout: cwd being a repository must not satisfy the required flag.
	_, err := ledgerProcess("init", "--api-key", "test-key", "--api-url", "https://example.invalid")
	if err == nil || !strings.Contains(err.Error(), `required flag(s) "repo" not set`) {
		t.Fatalf("missing --repo accepted or wrong error: %v", err)
	}
	previous := initRepo
	initRepo = " "
	t.Cleanup(func() { initRepo = previous })
	if err := runInit(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "--repo PATH is required") {
		t.Fatalf("empty repository accepted: %v", err)
	}
}
