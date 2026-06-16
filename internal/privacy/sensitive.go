package privacy

import (
	"path/filepath"
	"strings"
)

// sensitivePatterns lists glob-style patterns for sensitive file paths.
var sensitivePatterns = []string{
	// Environment and config
	".env",
	// Cryptographic material
	"*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
	// SSH
	"id_rsa*", "id_ed25519*", "id_ecdsa*", "known_hosts",
	// Cloud credentials
	"credentials", "credentials.json",
	// Secret-like names
	"*secret*", "*credential*", "*password*",
	// Infrastructure
	"terraform.tfvars", "*.auto.tfvars",
	// Token files
	".npmrc", ".pypirc", ".git-credentials", ".netrc",
}

// sensitivePathPrefixes are directory prefixes that make any file inside sensitive.
var sensitivePathPrefixes = []string{
	".ssh/",
	".aws/",
	".gcp/",
	".azure/",
	".docker/config.json",
}

// IsSensitivePath returns true if the given path matches any sensitive pattern.
func IsSensitivePath(path string) bool {
	if path == "" {
		return false
	}

	base := filepath.Base(path)
	lower := strings.ToLower(base)
	lowerPath := strings.ToLower(path)

	// Check directory prefixes
	for _, prefix := range sensitivePathPrefixes {
		if strings.Contains(lowerPath, prefix) {
			return true
		}
	}

	// .env and .env.* variants
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}

	for _, pattern := range sensitivePatterns {
		matched, err := filepath.Match(strings.ToLower(pattern), lower)
		if err == nil && matched {
			return true
		}
	}

	return false
}
