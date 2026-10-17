// Package scope decides whether a hook session is within the configured
// capture boundary. It deliberately returns only non-sensitive reasons for
// rejected sessions; hook payload content is never included in diagnostics.
package scope

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/secuardenai/secuarden-cli/internal/config"
	"github.com/secuardenai/secuarden-cli/internal/repository"
)

const (
	SkipMissingWorkingDirectory = "missing_working_directory"
	SkipUnresolvableDirectory   = "unresolvable_working_directory"
	SkipNonGitDirectory         = "non_git_directory"
	SkipDifferentRepository     = "different_repository"
	SkipUnapprovedRepository    = "unapproved_repository"
)

// Decision is the result of evaluating a session's originating directory.
type Decision struct {
	Allowed        bool
	Reason         string
	RepositoryRoot string
}

// Evaluate applies the configured scope to a hook session. In all mode the
// legacy user-wide behavior is retained, including for payloads without cwd.
// Scoped modes fail closed when the originating repository cannot be resolved.
func Evaluate(cfg *config.Config, cwd string) Decision {
	if cfg == nil || cfg.CaptureScope == "" || cfg.CaptureScope == config.CaptureScopeAll {
		return Decision{Allowed: true}
	}
	if cwd == "" {
		return Decision{Reason: SkipMissingWorkingDirectory}
	}
	if !filepath.IsAbs(cwd) {
		return Decision{Reason: SkipUnresolvableDirectory}
	}
	identity, err := repository.ResolvePath(cwd)
	if err != nil || !identity.RootValid || identity.Root == "" {
		if err != nil && filepath.IsAbs(cwd) {
			return Decision{Reason: classifyRepositoryError(err)}
		}
		return Decision{Reason: SkipUnresolvableDirectory}
	}
	root := filepath.Clean(identity.Root)
	decision := Decision{RepositoryRoot: root}
	switch cfg.CaptureScope {
	case config.CaptureScopeRepo:
		configuredRoot, err := config.CanonicalRepositoryPath(cfg.RepositoryRoot)
		if err != nil || configuredRoot != root {
			decision.Reason = SkipDifferentRepository
			return decision
		}
		decision.Allowed = true
		return decision
	case config.CaptureScopeApproved:
		for _, approved := range cfg.ApprovedRepositories {
			configuredRoot, err := config.CanonicalRepositoryPath(approved)
			if err == nil && configuredRoot == root {
				decision.Allowed = true
				return decision
			}
		}
		decision.Reason = SkipUnapprovedRepository
		return decision
	default:
		return Decision{Reason: fmt.Sprintf("invalid_scope_%s", cfg.CaptureScope)}
	}
}

func classifyRepositoryError(err error) string {
	if err == nil {
		return SkipUnresolvableDirectory
	}
	// ResolvePath intentionally does not expose the path or Git error in the
	// diagnostic category. This keeps scope counters safe for status output.
	if containsRepositoryHint(err.Error()) {
		return SkipNonGitDirectory
	}
	return SkipUnresolvableDirectory
}

func containsRepositoryHint(message string) bool {
	return strings.Contains(message, "not inside a Git repository")
}
