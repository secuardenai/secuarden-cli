package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func integrationRepository(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if out, err := exec.Command("git", "init", "--quiet", path).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	return path
}

func TestRepositoryIntegrationIsolationAndPersistence(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	a, b := integrationRepository(t), integrationRepository(t)
	cfg := &Config{SyncEnabled: true, APIKey: "legacy-key", APIURL: "https://legacy.invalid"}
	rootA, err := ConfigureIntegration(cfg, a, "key-a", "https://dev-a.invalid")
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := ConfigureIntegration(cfg, b, "key-b", "")
	if err != nil {
		t.Fatal(err)
	}
	if rootA == rootB {
		t.Fatal("repositories conflated")
	}
	if _, err := ConfigureIntegration(cfg, a, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := Save(cfg); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(a, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(nested, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{a, nested, alias} {
		loaded, err := LoadForRepository(path)
		if err != nil {
			t.Fatal(err)
		}
		if !loaded.SyncEnabled || loaded.APIKey != "key-a" || loaded.APIURL != "https://dev-a.invalid" {
			t.Fatal("repository A configuration not preserved")
		}
	}
	loaded, err := LoadForRepository(b)
	if err != nil || loaded.APIKey != "key-b" || loaded.APIURL != defaultAPIURL {
		t.Fatal("repository B configuration mixed with A")
	}
	unknown, err := LoadForRepository(integrationRepository(t))
	if err != nil || unknown.APIKey != "" || unknown.SyncEnabled || unknown.APIURL != defaultAPIURL {
		t.Fatal("legacy credentials used as fallback")
	}
	outside, err := LoadForRepository(t.TempDir())
	if err == nil || outside.APIKey != "" || outside.SyncEnabled {
		t.Fatal("non-repository inherited credentials")
	}
	configPath, _ := DefaultConfigPath()
	info, err := os.Stat(configPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credentials lack private permissions")
	}
}

func TestConfigureIntegrationRequiresGitRepository(t *testing.T) {
	cfg := &Config{}
	if _, err := ConfigureIntegration(cfg, t.TempDir(), "key", ""); err == nil {
		t.Fatal("accepted non-repository setup")
	}
	if len(cfg.RepositoryIntegrations) != 0 {
		t.Fatal("modified config before validation")
	}
}
