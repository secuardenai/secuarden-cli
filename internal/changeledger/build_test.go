package changeledger

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenameLimitDoesNotChangeDigest(t *testing.T) {
	dir := repoTest(t)
	for i := 0; i < 3; i++ {
		writeTest(t, dir, fmt.Sprintf("old-%d.txt", i), strings.Repeat(fmt.Sprintf("content %d\n", i), 100))
	}
	base := commitTest(t, dir, "base")
	for i := 0; i < 3; i++ {
		gitTest(t, dir, "mv", fmt.Sprintf("old-%d.txt", i), fmt.Sprintf("new-%d.txt", i))
		writeTest(t, dir, fmt.Sprintf("new-%d.txt", i), strings.Repeat(fmt.Sprintf("content %d\n", i), 99)+"edited\n")
	}
	head := commitTest(t, dir, "rename and edit")
	options := BuildOptions{Repository: dir, Base: base, Head: head}
	unlimited := mustBuild(t, options)
	gitTest(t, dir, "config", "diff.renameLimit", "1")
	limited := mustBuild(t, options)
	if limited.Digest != unlimited.Digest {
		t.Fatalf("user rename limit changed digest: paths before=%+v after=%+v", unlimited.ChangedPaths, limited.ChangedPaths)
	}
}

func TestSelectedRepositoryIgnoresInheritedGitDirectory(t *testing.T) {
	selected := repoTest(t)
	writeTest(t, selected, "selected.txt", "selected")
	selectedHead := commitTest(t, selected, "selected repository")
	other := repoTest(t)
	writeTest(t, other, "other.txt", "other")
	commitTest(t, other, "other repository")
	want := mustBuild(t, BuildOptions{Repository: selected, Base: "HEAD", Head: "HEAD"})
	t.Setenv("GIT_DIR", filepath.Join(other, ".git"))
	t.Setenv("GIT_WORK_TREE", other)
	got := mustBuild(t, BuildOptions{Repository: selected, Base: "HEAD", Head: "HEAD"})
	if got.HeadCommit != selectedHead || got.Repository != want.Repository || got.Digest != want.Digest {
		t.Fatalf("inherited Git environment selected wrong repository: got=%+v want=%+v", got, want)
	}
}

func TestDirtyAttributesDoNotChangeRevision(t *testing.T) {
	dir := repoTest(t)
	writeTest(t, dir, "old.txt", strings.Repeat("a line of text\n", 100))
	base := commitTest(t, dir, "base")
	gitTest(t, dir, "mv", "old.txt", "new.txt")
	writeTest(t, dir, "new.txt", strings.Repeat("a line of text\r\n", 99)+"edited\r\n")
	head := commitTest(t, dir, "rename with changed line endings")
	options := BuildOptions{Repository: dir, Base: base, Head: head}
	clean := mustBuild(t, options)
	writeTest(t, dir, ".gitattributes", "*.txt -diff\n")
	dirty := mustBuild(t, options)
	if clean.Digest != dirty.Digest {
		t.Fatalf("dirty attributes changed revision: clean=%+v dirty=%+v", clean.ChangedPaths, dirty.ChangedPaths)
	}
	gitTest(t, dir, "add", ".gitattributes")
	writeTest(t, dir, ".git/info/attributes", "*.txt -diff\n")
	globalAttributes := filepath.Join(t.TempDir(), "attributes")
	writeTest(t, filepath.Dir(globalAttributes), filepath.Base(globalAttributes), "*.txt -diff\n")
	gitTest(t, dir, "config", "core.attributesFile", globalAttributes)
	withLocalAttributes := mustBuild(t, options)
	if withLocalAttributes.Digest != clean.Digest {
		t.Fatalf("index or local attributes changed digest: %+v", withLocalAttributes.ChangedPaths)
	}
	// Committed attributes are revision inputs and must still be respected.
	options.Head = commitTest(t, dir, "commit binary attributes")
	withCommittedAttributes := mustBuild(t, options)
	for _, path := range withCommittedAttributes.ChangedPaths {
		if strings.HasPrefix(path.Status, "R") {
			t.Fatalf("committed binary attributes were ignored: %+v", path)
		}
	}
}

func gitTest(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeTest(t *testing.T, dir, name, value string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func commitTest(t *testing.T, dir, message string) string {
	t.Helper()
	gitTest(t, dir, "add", "-A")
	gitTest(t, dir, "commit", "-m", message)
	return gitTest(t, dir, "rev-parse", "HEAD")
}

func repoTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitTest(t, dir, "init", "-q", "-b", "main")
	gitTest(t, dir, "config", "user.name", "Test")
	gitTest(t, dir, "config", "user.email", "test@example.invalid")
	return dir
}

func TestMergeBaseRebaseForcePushAndDetachedHead(t *testing.T) {
	dir := repoTest(t)
	writeTest(t, dir, "base.txt", "base")
	base := commitTest(t, dir, "base")
	writeTest(t, dir, "main.txt", "main")
	mainTip := commitTest(t, dir, "main")
	gitTest(t, dir, "checkout", "-q", "-b", "feature", base)
	writeTest(t, dir, "feature.txt", "one")
	first := commitTest(t, dir, "feature one")
	options := BuildOptions{Repository: dir, Head: "feature", BaseRef: "main"}
	one, err := Build(options)
	if err != nil || one.Status != "complete" || one.BaseCommit != base || one.HeadCommit != first {
		t.Fatalf("first=%+v err=%v", one, err)
	}
	if len(one.InferredLinks) != 1 || one.InferredLinks[0].Method != "merge-base" {
		t.Fatalf("missing inferred selection: %+v", one.InferredLinks)
	}
	if link := one.InferredLinks[0]; link.Version != ContractVersion || link.Source != "git merge-base --all" || link.SourceVersion == "" {
		t.Fatalf("missing inferred link provenance: %+v", link)
	}
	// Rebase onto the advanced main branch changes the exact revision.
	gitTest(t, dir, "rebase", "main")
	rebased, err := Build(options)
	if err != nil || rebased.Status != "complete" || rebased.BaseCommit != mainTip || rebased.Digest == one.Digest {
		t.Fatalf("rebased=%+v err=%v", rebased, err)
	}
	// Replacing a branch tip represents a force push without a remote service.
	gitTest(t, dir, "reset", "--hard", "main")
	writeTest(t, dir, "feature.txt", "two")
	replacement := commitTest(t, dir, "replacement")
	forced, err := Build(options)
	if err != nil || forced.HeadCommit != replacement || forced.Digest == rebased.Digest {
		t.Fatalf("forced=%+v err=%v", forced, err)
	}
	gitTest(t, dir, "checkout", "-q", "--detach", replacement)
	detached, err := Build(BuildOptions{Repository: dir, Head: "HEAD", Base: mainTip})
	if err != nil || detached.Status != "complete" || detached.Digest != forced.Digest {
		t.Fatalf("detached=%+v err=%v", detached, err)
	}
}

func TestRenameDirtyContextAndStore(t *testing.T) {
	dir := repoTest(t)
	writeTest(t, dir, "old name.txt", "same")
	base := commitTest(t, dir, "base")
	gitTest(t, dir, "mv", "old name.txt", "new name.txt")
	commitTest(t, dir, "rename")
	options := BuildOptions{Repository: dir, Base: base}
	clean, err := Build(options)
	if err != nil || clean.Status != "complete" || len(clean.ChangedPaths) != 1 || clean.ChangedPaths[0].OldPath != "old name.txt" || clean.ChangedPaths[0].Path != "new name.txt" {
		t.Fatalf("rename=%+v err=%v", clean, err)
	}
	if clean.ChangedPaths[0].SourceVersion == "" || clean.Observations[0].SourceVersion == "" {
		t.Fatal("missing source versions")
	}
	for _, observation := range clean.Observations {
		if observation.Version != ContractVersion || observation.Source == "" || observation.SourceVersion == "" {
			t.Fatalf("missing observation provenance: %+v", observation)
		}
		if observation.Name == "worktree_dirty" && observation.Scope != "context" {
			t.Fatalf("worktree observation has wrong scope: %+v", observation)
		}
	}
	withDifferentSourceVersion := *clean
	withDifferentSourceVersion.ChangedPaths = append([]ChangedPath(nil), clean.ChangedPaths...)
	withDifferentSourceVersion.ChangedPaths[0].SourceVersion = "different git version"
	if err := withDifferentSourceVersion.setDigest(); err != nil || withDifferentSourceVersion.Digest != clean.Digest {
		t.Fatal("source version changed canonical digest")
	}
	writeTest(t, dir, "untracked.txt", "not in revision")
	dirty, err := Build(options)
	if err != nil || dirty.Digest != clean.Digest || dirty.WorktreeDirty == nil || !*dirty.WorktreeDirty {
		t.Fatalf("dirty=%+v err=%v", dirty, err)
	}
	store, err := Open(filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Put(clean); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Put(dirty)
	if err != nil {
		t.Fatal(err)
	}
	got, storedReceipt, err := store.Get(receipt.ChangeDigest)
	if err != nil || got.Digest != clean.Digest || got.WorktreeDirty == nil || !*got.WorktreeDirty {
		t.Fatalf("get=%+v err=%v", got, err)
	}
	if storedReceipt.StoredAt != receipt.StoredAt {
		t.Fatalf("receipt stored_at=%q, inspected stored_at=%q", receipt.StoredAt, storedReceipt.StoredAt)
	}
}

func TestSubmoduleChangesIgnoreUserDiffConfiguration(t *testing.T) {
	dir := repoTest(t)
	writeTest(t, dir, "source.txt", "first")
	firstCommit := commitTest(t, dir, "first source revision")
	writeTest(t, dir, "source.txt", "second")
	secondCommit := commitTest(t, dir, "second source revision")
	gitTest(t, dir, "update-index", "--add", "--cacheinfo", "160000,"+firstCommit+",dependency")
	base := commitIndexTest(t, dir, "gitlink points to first revision")
	gitTest(t, dir, "update-index", "--cacheinfo", "160000,"+secondCommit+",dependency")
	head := commitIndexTest(t, dir, "gitlink points to second revision")

	options := BuildOptions{Repository: dir, Base: base, Head: head}
	withoutIgnore := mustBuild(t, options)
	gitTest(t, dir, "config", "diff.ignoreSubmodules", "all")
	withIgnore := mustBuild(t, options)
	if withoutIgnore.Digest != withIgnore.Digest {
		t.Fatalf("diff.ignoreSubmodules changed digest: %s != %s", withoutIgnore.Digest, withIgnore.Digest)
	}
	if len(withIgnore.ChangedPaths) != 1 || withIgnore.ChangedPaths[0].Status != "M" || withIgnore.ChangedPaths[0].Path != "dependency" {
		t.Fatalf("changed gitlink missing under diff.ignoreSubmodules=all: %+v", withIgnore.ChangedPaths)
	}
}

func commitIndexTest(t *testing.T, dir, message string) string {
	t.Helper()
	gitTest(t, dir, "commit", "-m", message)
	return gitTest(t, dir, "rev-parse", "HEAD")
}

func mustBuild(t *testing.T, options BuildOptions) *Change {
	t.Helper()
	change, err := Build(options)
	if err != nil {
		t.Fatal(err)
	}
	if change.Status != "complete" {
		t.Fatalf("incomplete change: %+v", change)
	}
	return change
}

func TestUnavailableGitDataProducesGap(t *testing.T) {
	dir := repoTest(t)
	writeTest(t, dir, "x", "x")
	base := commitTest(t, dir, "base")
	c, err := Build(BuildOptions{Repository: dir, Base: base, Head: "missing-ref"})
	if err != nil || c.Status != "partial" || c.Digest != "" {
		t.Fatalf("change=%+v err=%v", c, err)
	}
	found := false
	for _, gap := range c.CaptureGaps {
		if gap.Code == "head_commit_unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing gap: %+v", c.CaptureGaps)
	}
	for _, gap := range c.CaptureGaps {
		if gap.Version != ContractVersion || gap.Source == "" || gap.SourceVersion == "" {
			t.Fatalf("missing capture gap provenance: %+v", gap)
		}
	}
	if _, err := Build(BuildOptions{Repository: t.TempDir(), Base: base}); err == nil {
		t.Fatal("non-repository should fail")
	}
}

func TestMissingTreeProducesPartialRecord(t *testing.T) {
	dir := repoTest(t)
	writeTest(t, dir, "file.txt", "base")
	base := commitTest(t, dir, "base")
	writeTest(t, dir, "file.txt", "head")
	head := commitTest(t, dir, "head")
	tree := gitTest(t, dir, "rev-parse", head+"^{tree}")
	// Remove an object only from this disposable fixture, modelling a damaged
	// or incompletely available object database.
	if err := os.Remove(filepath.Join(dir, ".git", "objects", tree[:2], tree[2:])); err != nil {
		t.Fatal(err)
	}
	change, err := Build(BuildOptions{Repository: dir, Base: base, Head: head})
	if err != nil || change.Status != "partial" || change.Digest != "" || len(change.CaptureGaps) == 0 {
		t.Fatalf("missing tree produced a complete revision: %+v err=%v", change, err)
	}
}

func TestAmbiguousMergeBaseProducesGap(t *testing.T) {
	dir := repoTest(t)
	writeTest(t, dir, "file.txt", "base")
	base := commitTest(t, dir, "base")
	tree := gitTest(t, dir, "rev-parse", base+"^{tree}")
	left := gitTest(t, dir, "commit-tree", tree, "-p", base, "-m", "left")
	right := gitTest(t, dir, "commit-tree", tree, "-p", base, "-m", "right")
	leftMerge := gitTest(t, dir, "commit-tree", tree, "-p", left, "-p", right, "-m", "left merge")
	rightMerge := gitTest(t, dir, "commit-tree", tree, "-p", right, "-p", left, "-m", "right merge")
	change, err := Build(BuildOptions{Repository: dir, BaseRef: leftMerge, Head: rightMerge})
	if err != nil || change.Status != "partial" || change.BaseCommit != "" || change.Digest != "" {
		t.Fatalf("ambiguous merge base was selected: %+v err=%v", change, err)
	}
	if len(change.CaptureGaps) != 1 || change.CaptureGaps[0].Code != "merge_base_ambiguous" {
		t.Fatalf("missing ambiguity gap: %+v", change.CaptureGaps)
	}
}

func TestReplacementRefsDoNotChangeExactRevision(t *testing.T) {
	dir := repoTest(t)
	writeTest(t, dir, "revision.txt", "base")
	base := commitTest(t, dir, "base")
	writeTest(t, dir, "revision.txt", "requested head")
	head := commitTest(t, dir, "requested head")
	requestedTree := gitTestEnv(t, dir, map[string]string{"GIT_NO_REPLACE_OBJECTS": "1"}, "rev-parse", head+"^{tree}")
	writeTest(t, dir, "revision.txt", "replacement commit")
	replacement := commitTest(t, dir, "replacement")
	gitTest(t, dir, "replace", head, replacement)

	// Confirm the fixture would be affected by replacement refs without the
	// ledger's pinned environment.
	if replacedTree := gitTest(t, dir, "rev-parse", head+"^{tree}"); replacedTree == requestedTree {
		t.Fatal("fixture replacement did not change the tree returned by Git")
	}
	change := mustBuild(t, BuildOptions{Repository: dir, Base: base, Head: head})
	if change.HeadCommit != head || change.HeadTree != requestedTree {
		t.Fatalf("replacement ref changed the recorded revision: head=%s tree=%s want tree=%s", change.HeadCommit, change.HeadTree, requestedTree)
	}
}

func gitTestEnv(t *testing.T, dir string, extra map[string]string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = os.Environ()
	for key, value := range extra {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}
