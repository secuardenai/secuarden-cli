package repository

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/privacy"
)

// Checkpoint contains observations, never file contents. Times bound a non-atomic
// filesystem scan; attribution describes observed transitions, not authorship proof.
type Checkpoint struct {
	PreviousSequence int         `json:"previous_sequence"`
	Kind             string      `json:"kind"`
	Status           string      `json:"status"`
	Reasons          []string    `json:"reasons"`
	StartedAt        string      `json:"started_at"`
	FinishedAt       string      `json:"finished_at"`
	Repository       string      `json:"repository,omitempty"`
	Root             string      `json:"root,omitempty"`
	Head             string      `json:"head,omitempty"`
	Tree             string      `json:"tree,omitempty"`
	Branch           string      `json:"branch,omitempty"`
	Files            []FileState `json:"files"`
}

type FileState struct {
	Path         string `json:"path"`
	Index        string `json:"index,omitempty"` // mode, Git object ID, conflict stage
	Staged       string `json:"staged,omitempty"`
	Unstaged     string `json:"unstaged,omitempty"`
	Untracked    bool   `json:"untracked"`
	Sensitive    bool   `json:"is_sensitive"`
	Status       string `json:"status"`
	Digest       string `json:"sha256,omitempty"`
	ObservedAt   string `json:"observed_at"`
	PreExisting  bool   `json:"pre_existing"`
	Attribution  string `json:"attribution"`
	BeforeDigest string `json:"before_sha256,omitempty"`
}

// CaptureCheckpoint includes tracked files and non-ignored untracked files.
// Both privacy modes permit paths and hashes, including sensitive files; no
// contents, diffs, symlink targets, or raw Git error messages are retained.
func CaptureCheckpoint(cwd, kind string) *Checkpoint {
	c := &Checkpoint{Kind: kind, Status: "complete", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Reasons: []string{}, Files: []FileState{}}
	defer func() { c.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano) }()
	fail := func(reason string) {
		c.Status = "partial"
		for _, r := range c.Reasons {
			if r == reason {
				return
			}
		}
		c.Reasons = append(c.Reasons, reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	git := func(dir string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
		b, e := cmd.Output()
		return string(b), e
	}
	if cwd == "" {
		c.Status = "failed"
		c.Reasons = append(c.Reasons, "missing_working_directory")
		return c
	}
	root, err := git(cwd, "rev-parse", "--show-toplevel")
	if err != nil {
		c.Status = "failed"
		c.Reasons = append(c.Reasons, "repository_unavailable")
		return c
	}
	c.Root = strings.TrimSpace(root)
	if real, err := filepath.EvalSymlinks(c.Root); err == nil {
		c.Root = real
	}
	c.Repository = "local:" + filepath.ToSlash(c.Root)
	if remote, err := git(c.Root, "remote", "get-url", "origin"); err == nil {
		if canonical, _, err := NormalizeRemote(strings.TrimSpace(remote)); err == nil {
			c.Repository = canonical
		}
	}
	head, err := git(c.Root, "rev-parse", "--verify", "HEAD")
	if err != nil {
		fail("head_unavailable")
	} else {
		c.Head = strings.TrimSpace(head)
	}
	tree, err := git(c.Root, "rev-parse", "--verify", "HEAD^{tree}")
	if err == nil {
		c.Tree = strings.TrimSpace(tree)
	} else {
		fail("tree_unavailable")
	}
	branch, err := git(c.Root, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err == nil {
		c.Branch = strings.TrimSpace(branch)
	} else if c.Head != "" {
		c.Branch = "(detached)"
	} else {
		fail("branch_unavailable")
	}
	status, err := git(c.Root, "-c", "status.renames=false", "-c", "diff.renames=false", "status", "--porcelain", "-z", "--untracked-files=all")
	if err != nil {
		fail("status_failed")
		return c
	}
	index, err := git(c.Root, "ls-files", "--stage", "-z")
	if err != nil {
		fail("index_failed")
		return c
	}
	files := map[string]*FileState{}
	get := func(path string) *FileState {
		if files[path] == nil {
			files[path] = &FileState{Path: path, Attribution: "unattributed"}
		}
		return files[path]
	}
	for _, entry := range strings.Split(index, "\x00") {
		if entry == "" {
			continue
		}
		meta, path, ok := strings.Cut(entry, "\t")
		if !ok {
			fail("index_parse_failed")
			continue
		}
		f := get(path)
		if f.Index != "" {
			f.Index += ";"
		}
		f.Index += meta
	}
	for _, entry := range strings.Split(status, "\x00") {
		if len(entry) < 4 {
			continue
		}
		f := get(entry[3:])
		if entry[:2] == "??" {
			f.Untracked = true
		} else {
			f.Staged = strings.TrimSpace(entry[:1])
			f.Unstaged = strings.TrimSpace(entry[1:2])
		}
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var total int64
	for _, path := range paths {
		f := files[path]
		f.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		f.Sensitive = privacy.IsSensitivePath(filepath.Join(c.Root, filepath.FromSlash(path)))
		full := filepath.Join(c.Root, filepath.FromSlash(path))
		// Never follow symlinks, including a replaced parent directory.
		parent, e := filepath.EvalSymlinks(filepath.Dir(full))
		rel, re := filepath.Rel(c.Root, parent)
		st, se := os.Lstat(full)
		switch {
		case ctx.Err() != nil || total >= 256<<20:
			f.Status = "omitted_limit"
			fail("scan_limit")
		case e != nil && os.IsNotExist(se):
			f.Status = "deleted"
		case e != nil || re != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || parent != filepath.Dir(full):
			f.Status = "omitted_unsafe_path"
			fail("unsafe_path")
		case os.IsNotExist(se):
			f.Status = "deleted"
		case se != nil:
			f.Status = "unreadable"
			fail("file_read_failed")
		case !st.Mode().IsRegular():
			f.Status = "omitted_nonregular"
			fail("nonregular_file")
		case st.Size() > 32<<20:
			f.Status = "omitted_limit"
			fail("scan_limit")
		default:
			file, err := os.Open(full)
			if err != nil {
				f.Status = "unreadable"
				fail("file_read_failed")
				break
			}
			opened, err := file.Stat()
			if err != nil || !os.SameFile(st, opened) {
				file.Close()
				f.Status = "unstable"
				fail("file_changed_during_scan")
				break
			}
			h := sha256.New()
			n, err := io.Copy(h, io.LimitReader(file, (32<<20)+1))
			after, ae := file.Stat()
			file.Close()
			total += n
			if err != nil || ae != nil {
				f.Status = "unreadable"
				fail("file_read_failed")
			} else if n > 32<<20 || n != st.Size() || !after.ModTime().Equal(st.ModTime()) {
				f.Status = "unstable"
				fail("file_changed_during_scan")
			} else {
				f.Status = "present"
				f.Digest = fmt.Sprintf("%x", h.Sum(nil))
			}
		}
		c.Files = append(c.Files, *f)
	}
	endStatus, err := git(c.Root, "-c", "status.renames=false", "-c", "diff.renames=false", "status", "--porcelain", "-z", "--untracked-files=all")
	endIndex, ie := git(c.Root, "ls-files", "--stage", "-z")
	endHead, he := git(c.Root, "rev-parse", "--verify", "HEAD")
	if err != nil || ie != nil || endStatus != status || endIndex != index || (he == nil && strings.TrimSpace(endHead) != c.Head) {
		fail("repository_changed_during_scan")
	}
	return c
}
