package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsToAllScope(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CaptureScope != CaptureScopeAll {
		t.Fatalf("capture scope = %q, want %q", cfg.CaptureScope, CaptureScopeAll)
	}
}

func TestSaveCanonicalizesAndDeduplicatesApprovedRepositories(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	alias := filepath.Join(root, ".")
	if err := Save(&Config{
		CaptureScope:         CaptureScopeApproved,
		ApprovedRepositories: []string{root, alias},
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	canonicalRoot, _ := CanonicalRepositoryPath(root)
	if len(cfg.ApprovedRepositories) != 1 || cfg.ApprovedRepositories[0] != canonicalRoot {
		t.Fatalf("approved repositories = %#v", cfg.ApprovedRepositories)
	}
	path, _ := DefaultConfigPath()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions = %v, want 0600", err)
	}
}
