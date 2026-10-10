package config

import (
	"fmt"
	"strings"

	"github.com/secuardenai/secuarden-cli/internal/repository"
)

// ForRepository resolves nested directories and symlinks to a Git root. A
// missing or unavailable repository fails closed without using global keys.
func ForRepository(cfg *Config, path string) (*Config, error) {
	result := *cfg
	result.APIKey, result.APIURL, result.SyncEnabled = "", defaultAPIURL, false
	identity, err := repository.ResolveCurrent(path)
	if err != nil {
		return &result, err
	}
	if integration, ok := cfg.RepositoryIntegrations[identity.Root]; ok {
		result.APIKey = integration.APIKey
		result.SyncEnabled = integration.SyncEnabled && strings.TrimSpace(integration.APIKey) != ""
		if integration.APIURL != "" {
			result.APIURL = integration.APIURL
		}
	}
	return &result, nil
}

func LoadForRepository(path string) (*Config, error) {
	cfg, err := Load()
	if err != nil {
		return nil, err
	}
	return ForRepository(cfg, path)
}

// ConfigureIntegration updates only this repository; omitting a key preserves
// its existing integration. New repositories remain local-only without a key.
func ConfigureIntegration(cfg *Config, path, key, apiURL string) (string, error) {
	identity, err := repository.ResolveCurrent(path)
	if err != nil {
		return "", fmt.Errorf("per-repository setup requires a Git repository: %w", err)
	}
	if cfg.RepositoryIntegrations == nil {
		cfg.RepositoryIntegrations = map[string]Integration{}
	}
	integration := cfg.RepositoryIntegrations[identity.Root]
	if key = strings.TrimSpace(key); key != "" {
		integration.APIKey, integration.SyncEnabled = key, true
	}
	if apiURL = strings.TrimSpace(apiURL); apiURL != "" {
		integration.APIURL = apiURL
	}
	if integration.APIURL == "" {
		integration.APIURL = defaultAPIURL
	}
	cfg.RepositoryIntegrations[identity.Root] = integration
	return identity.Root, nil
}
