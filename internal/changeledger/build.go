package changeledger

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/repository"
)

type BuildOptions struct {
	Repository string
	Head       string
	Base       string // exact commit or rev; mutually exclusive with BaseRef
	BaseRef    string // merge-base with head is selected
}

// Build observes immutable Git objects. A failed essential observation returns
// a partial Change with typed gaps and no digest, never a guessed revision.
func Build(options BuildOptions) (*Change, error) {
	if options.Base != "" && options.BaseRef != "" {
		return nil, fmt.Errorf("base and base-ref are mutually exclusive")
	}
	if options.Base == "" && options.BaseRef == "" {
		return nil, fmt.Errorf("base or base-ref is required")
	}
	if options.Repository == "" {
		options.Repository = "."
	}
	if options.Head == "" {
		options.Head = "HEAD"
	}
	root, err := filepath.Abs(options.Repository)
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		root = filepath.Dir(root)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	env := gitEnvironment()
	git := func(args ...string) (string, error) {
		command := exec.CommandContext(ctx, "git", append([]string{"-C", root, "--no-pager"}, args...)...)
		command.Env = env
		b, err := command.Output()
		return strings.TrimSuffix(string(b), "\n"), err
	}
	// Resolve identity through the same isolated Git environment as the objects.
	// A caller's hook or shell may otherwise redirect --repo to a different DB.
	root, err = git("rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("%q is not inside a Git repository: %w", options.Repository, err)
	}
	canonical := "local:" + filepath.ToSlash(root)
	identitySource := "git rev-parse --show-toplevel"
	if remote, err := git("remote", "get-url", "origin"); err == nil && remote != "" {
		if normalized, _, err := repository.NormalizeRemote(remote); err == nil {
			canonical = normalized
			identitySource = "git remote get-url origin (normalized)"
		}
	}
	version, err := git("--version")
	if err != nil {
		version = "unknown"
	}
	c := &Change{Version: ContractVersion, Status: "partial", Repository: canonical,
		ChangedPaths: []ChangedPath{}, Observations: []Observation{}, InferredLinks: []InferredLink{}, CaptureGaps: []CaptureGap{}}
	observe := func(name, value, source string) {
		scope := "revision"
		if name == "worktree_dirty" {
			scope = "context"
		}
		c.Observations = append(c.Observations, Observation{
			Version: ContractVersion, Name: name, Value: value, Scope: scope,
			Source: source, SourceVersion: version,
		})
	}
	gap := func(code, source string) {
		c.CaptureGaps = append(c.CaptureGaps, CaptureGap{
			Version: ContractVersion, Code: code, Source: source, SourceVersion: version,
		})
	}
	observe("repository", c.Repository, identitySource)
	resolve := func(ref, name string) string {
		value, err := git("rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
		if err != nil {
			gap(name+"_unavailable", "git rev-parse")
			return ""
		}
		observe(name, value, "git rev-parse")
		return value
	}
	c.HeadCommit = resolve(options.Head, "head_commit")
	if options.BaseRef != "" {
		baseTip := resolve(options.BaseRef, "base_ref_tip")
		if baseTip != "" && c.HeadCommit != "" {
			bases, err := git("merge-base", "--all", baseTip, c.HeadCommit)
			if err != nil || bases == "" {
				gap("merge_base_unavailable", "git merge-base --all")
			} else {
				parts := strings.Fields(bases)
				// Multiple best bases are ambiguous in criss-cross histories.
				if len(parts) != 1 {
					gap("merge_base_ambiguous", "git merge-base --all")
				} else {
					c.BaseCommit = parts[0]
					observe("base_commit", c.BaseCommit, "git merge-base --all")
					c.InferredLinks = append(c.InferredLinks, InferredLink{
						Version: ContractVersion, Kind: "base_selection", From: baseTip,
						To: c.BaseCommit, Method: "merge-base", Source: "git merge-base --all",
						SourceVersion: version,
					})
				}
			}
		}
	} else {
		c.BaseCommit = resolve(options.Base, "base_commit")
	}
	tree := func(commit, name string) string {
		if commit == "" {
			return ""
		}
		value, err := git("rev-parse", "--verify", commit+"^{tree}")
		if err != nil {
			gap(name+"_unavailable", "git rev-parse")
			return ""
		}
		observe(name, value, "git rev-parse")
		return value
	}
	c.BaseTree = tree(c.BaseCommit, "base_tree")
	c.HeadTree = tree(c.HeadCommit, "head_tree")
	if c.BaseTree != "" && c.HeadTree != "" {
		// -z preserves unusual filenames and rename pairs without quoting.
		output, err := diffTrees(ctx, git, env, c.BaseTree, c.HeadTree)
		if err != nil {
			gap("changed_paths_unavailable", "git diff --name-status -z")
		} else if paths, err := parsePaths(output, version); err != nil {
			gap("changed_paths_invalid", "git diff --name-status -z")
		} else {
			c.ChangedPaths = paths
			observe("changed_paths", fmt.Sprintf("%d", len(paths)), "git diff --name-status -z")
		}
	}
	if status, err := git("status", "--porcelain", "-z", "--untracked-files=all"); err == nil {
		dirty := status != ""
		c.WorktreeDirty = &dirty
		observe("worktree_dirty", fmt.Sprint(dirty), "git status --porcelain -z")
	} else {
		gap("worktree_status_unavailable", "git status --porcelain -z")
	}
	if c.BaseCommit != "" && c.HeadCommit != "" && c.BaseTree != "" && c.HeadTree != "" && !hasEssentialGap(c.CaptureGaps) {
		c.Status = "complete"
		if err := c.setDigest(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func gitEnvironment() []string {
	// Repository-local variables reported by `git rev-parse --local-env-vars`,
	// plus namespace and our explicit safety overrides. Keep ordinary user
	// configuration (including origin) while discarding inherited repo state.
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS",
			"GIT_CONFIG_COUNT", "GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE",
			"GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE", "GIT_INDEX_FILE",
			"GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE", "GIT_PREFIX",
			"GIT_SHALLOW_FILE", "GIT_COMMON_DIR", "GIT_NAMESPACE",
			"GIT_OPTIONAL_LOCKS", "GIT_NO_LAZY_FETCH":
			continue
		}
		env = append(env, entry)
	}
	return append(env, "GIT_OPTIONAL_LOCKS=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1")
}

func hasEssentialGap(gaps []CaptureGap) bool {
	for _, g := range gaps {
		if g.Code != "worktree_status_unavailable" {
			return true
		}
	}
	return false
}

func parsePaths(output, version string) ([]ChangedPath, error) {
	paths := []ChangedPath{}
	if output == "" {
		return paths, nil
	}
	parts := strings.Split(output, "\x00")
	for i := 0; i < len(parts)-1; {
		status := parts[i]
		i++
		if i >= len(parts)-1 || status == "" {
			return nil, fmt.Errorf("invalid diff record")
		}
		path := ChangedPath{Status: status, Path: parts[i], Source: "git diff --name-status -z", SourceVersion: version}
		i++
		if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
			if i >= len(parts)-1 {
				return nil, fmt.Errorf("invalid rename record")
			}
			path.OldPath, path.Path = path.Path, parts[i]
			i++
		}
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Path == paths[j].Path {
			return paths[i].OldPath < paths[j].OldPath
		}
		return paths[i].Path < paths[j].Path
	})
	return paths, nil
}
