// Package repository resolves and normalizes local Git repository identities.
package repository

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Identity is a repository identity derived without network access.
type Identity struct {
	Canonical string   `json:"canonical"`
	Name      string   `json:"name"`
	Root      string   `json:"root,omitempty"`
	Remote    string   `json:"remote,omitempty"`
	RootValid bool     `json:"-"`
	Roots     []string `json:"-"`
}

// CapturedRef is the repository evidence stored for a captured session.
type CapturedRef struct {
	SessionID        string
	GitRepoURL       string
	WorkingDirectory string
}

// Group associates one normalized repository with captured sessions.
type Group struct {
	Identity   Identity
	SessionIDs []string
}

// ResolvePath resolves an existing path to its containing Git repository.
func ResolvePath(path string) (Identity, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Identity{}, fmt.Errorf("resolve repository path: %w", err)
	}
	if evaluated, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = evaluated
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return Identity{}, fmt.Errorf("repository path %q: %w", path, err)
	}
	if !info.IsDir() {
		absolute = filepath.Dir(absolute)
	}
	root, err := gitOutput(absolute, "rev-parse", "--show-toplevel")
	if err != nil {
		return Identity{}, fmt.Errorf("%q is not inside a Git repository", path)
	}
	root = filepath.Clean(root)
	if evaluated, err := filepath.EvalSymlinks(root); err == nil {
		root = evaluated
	}
	remote, _ := gitOutput(root, "remote", "get-url", "origin")
	if remote != "" {
		canonical, name, err := NormalizeRemote(remote)
		if err == nil {
			return Identity{Canonical: canonical, Name: name, Root: root, Remote: remote, RootValid: true, Roots: []string{root}}, nil
		}
	}
	return Identity{
		Canonical: "local:" + filepath.ToSlash(root), Name: filepath.Base(root),
		Root: root, RootValid: true, Roots: []string{root},
	}, nil
}

// ResolveCurrent resolves the repository containing dir.
func ResolveCurrent(dir string) (Identity, error) {
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return Identity{}, err
		}
	}
	return ResolvePath(dir)
}

// NormalizeRemote normalizes common Git SSH and HTTPS identities without
// contacting the remote host.
func NormalizeRemote(raw string) (canonical, name string, err error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", fmt.Errorf("empty repository identity")
	}

	// SCP-style Git SSH syntax: git@host:owner/repository.git.
	if !strings.Contains(value, "://") {
		if at := strings.LastIndex(value, "@"); at >= 0 {
			value = value[at+1:]
		}
		if colon := strings.Index(value, ":"); colon > 0 {
			value = value[:colon] + "/" + value[colon+1:]
		}
		value = strings.TrimPrefix(value, "//")
		if strings.Count(value, "/") >= 2 {
			return normalizeHostPath(value)
		}
	}

	if strings.Contains(value, "://") {
		parsed, parseErr := url.Parse(value)
		if parseErr != nil || parsed.Hostname() == "" {
			return "", "", fmt.Errorf("invalid repository remote %q", raw)
		}
		return normalizeHostPath(parsed.Hostname() + "/" + strings.TrimPrefix(parsed.Path, "/"))
	}

	// A canonical host/path identity is accepted as-is. owner/repository and
	// short names are resolved against captured repositories by Match.
	if strings.Count(value, "/") >= 2 {
		return normalizeHostPath(value)
	}
	trimmed := trimRepositorySuffix(value)
	if trimmed == "" {
		return "", "", fmt.Errorf("invalid repository identity %q", raw)
	}
	return trimmed, repositoryName(trimmed), nil
}

func normalizeHostPath(value string) (string, string, error) {
	parts := strings.SplitN(strings.Trim(value, "/"), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid repository identity %q", value)
	}
	host := strings.ToLower(parts[0])
	path := trimRepositorySuffix(strings.Trim(parts[1], "/"))
	if path == "" {
		return "", "", fmt.Errorf("invalid repository identity %q", value)
	}
	canonical := host + "/" + path
	return canonical, repositoryName(path), nil
}

func trimRepositorySuffix(value string) string {
	value = strings.TrimSpace(strings.TrimSuffix(value, "/"))
	value = strings.TrimSuffix(value, ".git")
	return strings.TrimSuffix(value, "/")
}

func repositoryName(identity string) string {
	identity = strings.TrimSuffix(identity, "/")
	if slash := strings.LastIndex(identity, "/"); slash >= 0 {
		return identity[slash+1:]
	}
	return strings.TrimPrefix(identity, "local:")
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// GroupCaptured normalizes stored repository evidence and groups session IDs.
// Git is consulted only for stored working directories that still exist.
func GroupCaptured(refs []CapturedRef) []Group {
	byCanonical := map[string]*Group{}
	for _, ref := range refs {
		identity := identityForCaptured(ref)
		if identity.Canonical == "" {
			identity = Identity{Canonical: "unknown", Name: "unknown"}
		}
		group := byCanonical[identity.Canonical]
		if group == nil {
			copy := Group{Identity: identity, SessionIDs: make([]string, 0)}
			byCanonical[identity.Canonical] = &copy
			group = &copy
		} else if identity.RootValid {
			group.Identity.Roots = appendUnique(group.Identity.Roots, identity.Roots...)
			if !group.Identity.RootValid {
				group.Identity.Root, group.Identity.RootValid = identity.Root, true
			}
		}
		group.SessionIDs = append(group.SessionIDs, ref.SessionID)
	}
	keys := make([]string, 0, len(byCanonical))
	for key := range byCanonical {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Group, 0, len(keys))
	for _, key := range keys {
		group := byCanonical[key]
		sort.Strings(group.SessionIDs)
		result = append(result, *group)
	}
	return result
}

func identityForCaptured(ref CapturedRef) Identity {
	if ref.GitRepoURL != "" {
		if canonical, name, err := NormalizeRemote(ref.GitRepoURL); err == nil {
			identity := Identity{Canonical: canonical, Name: name, Remote: ref.GitRepoURL}
			if ref.WorkingDirectory != "" {
				if resolved, err := ResolvePath(ref.WorkingDirectory); err == nil && resolved.Canonical == canonical {
					identity.Root, identity.RootValid, identity.Roots = resolved.Root, true, []string{resolved.Root}
				}
			}
			return identity
		}
	}
	if ref.WorkingDirectory != "" {
		if resolved, err := ResolvePath(ref.WorkingDirectory); err == nil {
			return resolved
		}
		clean := filepath.Clean(ref.WorkingDirectory)
		if filepath.IsAbs(clean) {
			return Identity{Canonical: "unverified:" + filepath.ToSlash(clean), Name: filepath.Base(clean)}
		}
	}
	return Identity{}
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]bool, len(values)+len(additions))
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range additions {
		if value != "" && !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	sort.Strings(values)
	return values
}

// Match selects captured groups for an explicit or current repository.
func Match(selected Identity, groups []Group) []Group {
	result := make([]Group, 0, 1)
	for _, group := range groups {
		if group.Identity.Canonical == selected.Canonical {
			result = append(result, group)
		}
	}
	return result
}

// ResolveIdentity resolves a non-path identity against captured repositories.
func ResolveIdentity(value string, groups []Group) (Identity, error) {
	normalized, name, err := NormalizeRemote(value)
	if err != nil {
		return Identity{}, err
	}
	candidates := make([]Identity, 0)
	for _, group := range groups {
		canonical := group.Identity.Canonical
		match := canonical == normalized
		if !match && strings.Count(normalized, "/") == 1 {
			match = strings.HasSuffix(canonical, "/"+normalized)
		}
		if !match && !strings.Contains(normalized, "/") {
			match = group.Identity.Name == normalized
		}
		if match {
			candidates = append(candidates, group.Identity)
		}
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	if len(candidates) > 1 {
		identities := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			identities = append(identities, candidate.Canonical)
		}
		sort.Strings(identities)
		return Identity{}, fmt.Errorf("repository %q is ambiguous; use one of: %s", value, strings.Join(identities, ", "))
	}

	// A fully qualified remote or owner/repository is a valid explicit empty
	// selection. A short unmatched name cannot be resolved authoritatively.
	if strings.Contains(value, "://") || strings.Contains(value, "@") || strings.Count(normalized, "/") >= 1 {
		return Identity{Canonical: normalized, Name: name}, nil
	}
	return Identity{}, fmt.Errorf("repository %q was not found; use a path, remote URL, or owner/repository identity", value)
}

// DisplayPath derives a safe presentation path from an already-stored path.
type DisplayPath struct {
	Original   string `json:"file_path"`
	Display    string `json:"display_path"`
	Repository string `json:"repository"`
	External   bool   `json:"external"`
}

// FormatPath renders stored without changing Original.
func FormatPath(stored string, repo Identity, home string, absolute, prefixRepository bool) DisplayPath {
	clean := filepath.Clean(stored)
	result := DisplayPath{Original: stored, Display: clean, Repository: repo.Canonical}
	if stored == "" {
		result.Display = ""
		return result
	}

	if !filepath.IsAbs(clean) {
		// Without an absolute captured working directory, containment cannot be
		// proven. Keep the cleaned stored value but do not claim it is local.
		result.Display = filepath.ToSlash(clean)
		result.External = true
		return result
	}

	inside := false
	relative := ""
	roots := append([]string{}, repo.Roots...)
	if repo.RootValid && repo.Root != "" {
		roots = appendUnique(roots, repo.Root)
	}
	for _, root := range roots {
		if rel, err := filepath.Rel(filepath.Clean(root), clean); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			inside, relative = true, rel
			break
		}
	}
	result.External = !inside
	if absolute {
		result.Display = clean
		return result
	}
	if inside {
		result.Display = filepath.ToSlash(relative)
		if prefixRepository && repo.Name != "" {
			result.Display = filepath.ToSlash(filepath.Join(repo.Name, result.Display))
		}
		return result
	}
	if home != "" {
		home = filepath.Clean(home)
		if rel, err := filepath.Rel(home, clean); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			result.Display = filepath.ToSlash(filepath.Join("~", rel))
		}
	}
	return result
}
