package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const defaultAPIURL = "https://app.secuarden.ai"

const (
	CaptureScopeAll      = "all"
	CaptureScopeRepo     = "repo"
	CaptureScopeApproved = "approved"
)

// Config holds the user-level Secuarden configuration.
// Stored at ~/.secuarden/config.json.
// SyncEnabled = false (default) → local SQLite only, no network calls.
// SyncEnabled = true           → session-end also POSTs to the SaaS and
//
//	prints developer feedback to stdout.
type Config struct {
	RepositoryIntegrations map[string]Integration `json:"repository_integrations,omitempty"`
	SyncEnabled            bool                   `json:"sync_enabled"`
	APIKey                 string                 `json:"api_key,omitempty"`
	APIURL                 string                 `json:"api_url,omitempty"`
	PrivacyMode            string                 `json:"privacy_mode,omitempty"`
	CaptureScope           string                 `json:"capture_scope,omitempty"`
	RepositoryRoot         string                 `json:"repository_root,omitempty"`
	ApprovedRepositories   []string               `json:"approved_repositories"`
}

// Integration is SaaS configuration for exactly one canonical local repository.
// Legacy top-level credentials are retained for compatibility but are never a
// fallback for repository-scoped SaaS operations.
type ReceiptOptions struct {
	Mode        string            `json:"mode"`
	BaseRef     string            `json:"base_ref,omitempty"`
	BranchBases map[string]string `json:"branch_bases,omitempty"`
}

type Integration struct {
	Receipt     ReceiptOptions `json:"receipt,omitempty"`
	SyncEnabled bool           `json:"sync_enabled"`
	APIKey      string         `json:"api_key,omitempty"`
	APIURL      string         `json:"api_url,omitempty"`
}

// DefaultConfigPath returns ~/.secuarden/config.json.
func DefaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".secuarden", "config.json"), nil
}

// Load reads the config file. Returns a zero-value Config (sync disabled)
// if the file does not exist — never returns an error for a missing file.
func Load() (*Config, error) {
	path, err := DefaultConfigPath()
	if err != nil {
		return &Config{}, fmt.Errorf("config path: %w", err)
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Config{APIURL: defaultAPIURL, PrivacyMode: "redacted_content", CaptureScope: CaptureScopeAll}, nil
	}
	if err != nil {
		return &Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return &Config{}, fmt.Errorf("parse config: %w", err)
	}

	if cfg.APIURL == "" {
		cfg.APIURL = defaultAPIURL
	}
	if cfg.PrivacyMode == "" {
		cfg.PrivacyMode = "redacted_content"
	}
	if cfg.PrivacyMode != "redacted_content" && cfg.PrivacyMode != "metadata_only" {
		return &Config{}, fmt.Errorf("privacy_mode must be redacted_content or metadata_only")
	}
	if err := cfg.normalizeScope(); err != nil {
		return &Config{}, err
	}
	return &cfg, nil
}

// Save writes the config to ~/.secuarden/config.json.
func Save(cfg *Config) error {
	path, err := DefaultConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if cfg.APIURL == "" {
		cfg.APIURL = defaultAPIURL
	}
	if cfg.PrivacyMode == "" {
		cfg.PrivacyMode = "redacted_content"
	}
	if cfg.PrivacyMode != "redacted_content" && cfg.PrivacyMode != "metadata_only" {
		return fmt.Errorf("privacy_mode must be redacted_content or metadata_only")
	}
	if err := cfg.normalizeScope(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}

func (c *Config) normalizeScope() error {
	if c.CaptureScope == "" {
		c.CaptureScope = CaptureScopeAll
	}
	for i, value := range c.ApprovedRepositories {
		root, err := canonicalConfiguredPath(value)
		if err != nil {
			return fmt.Errorf("approved_repositories[%d]: %w", i, err)
		}
		c.ApprovedRepositories[i] = root
	}
	c.ApprovedRepositories = uniqueSorted(c.ApprovedRepositories)
	switch c.CaptureScope {
	case CaptureScopeAll:
		// No repository is needed for the backward-compatible user-wide mode.
	case CaptureScopeRepo:
		if c.RepositoryRoot == "" {
			return fmt.Errorf("capture_scope repo requires repository_root")
		}
		root, err := canonicalConfiguredPath(c.RepositoryRoot)
		if err != nil {
			return fmt.Errorf("repository_root: %w", err)
		}
		c.RepositoryRoot = root
	case CaptureScopeApproved:
		// An empty allowlist is valid but captures no scoped repositories.
	default:
		return fmt.Errorf("capture_scope must be all, repo, or approved")
	}
	return nil
}

func canonicalConfiguredPath(value string) (string, error) {
	value = filepath.Clean(value)
	if value == "." || !filepath.IsAbs(value) {
		return "", fmt.Errorf("must be an absolute path")
	}
	if evaluated, err := filepath.EvalSymlinks(value); err == nil {
		value = evaluated
	}
	return filepath.Clean(value), nil
}

// CanonicalRepositoryPath normalizes a configured repository root without
// requiring the caller to know whether it is a symlink.
func CanonicalRepositoryPath(value string) (string, error) {
	return canonicalConfiguredPath(value)
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
