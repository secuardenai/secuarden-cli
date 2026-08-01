package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const defaultAPIURL = "https://app.secuarden.ai"

// Config holds the user-level Secuarden configuration.
// Stored at ~/.secuarden/config.json.
// SyncEnabled = false (default) → local SQLite only, no network calls.
// SyncEnabled = true           → session-end also POSTs to the SaaS and
//
//	prints developer feedback to stdout.
type Config struct {
	SyncEnabled bool   `json:"sync_enabled"`
	APIKey      string `json:"api_key,omitempty"`
	APIURL      string `json:"api_url,omitempty"`
	PrivacyMode string `json:"privacy_mode,omitempty"`
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
		return &Config{}, nil
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
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}
