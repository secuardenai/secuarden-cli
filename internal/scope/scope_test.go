package scope

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/config"
)

func TestEvaluateAllAllowsMissingWorkingDirectory(t *testing.T) {
	decision := Evaluate(&config.Config{CaptureScope: config.CaptureScopeAll}, "")
	if !decision.Allowed {
		t.Fatalf("all scope rejected missing cwd: %#v", decision)
	}
}

func TestEvaluateRepoAcceptsAndRejectsRepositories(t *testing.T) {
	root := initRepository(t, "allowed")
	other := initRepository(t, "other")
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{CaptureScope: config.CaptureScopeRepo, RepositoryRoot: root}

	if decision := Evaluate(cfg, filepath.Join(root, "nested")); !decision.Allowed {
		t.Fatalf("repo scope rejected originating repository: %#v", decision)
	}
	if decision := Evaluate(cfg, other); decision.Allowed || decision.Reason != SkipDifferentRepository {
		t.Fatalf("repo scope accepted another repository: %#v", decision)
	}
}

func TestEvaluateApprovedAndCanonicalizesSymlink(t *testing.T) {
	root := initRepository(t, "approved")
	other := initRepository(t, "other")
	link := filepath.Join(t.TempDir(), "repo-link")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	cfg := &config.Config{CaptureScope: config.CaptureScopeApproved, ApprovedRepositories: []string{root}}
	canonicalRoot, _ := config.CanonicalRepositoryPath(root)
	if decision := Evaluate(cfg, link); !decision.Allowed || decision.RepositoryRoot != canonicalRoot {
		t.Fatalf("approved scope did not canonicalize symlink: %#v", decision)
	}
	if decision := Evaluate(cfg, other); decision.Allowed || decision.Reason != SkipUnapprovedRepository {
		t.Fatalf("approved scope accepted unapproved repository: %#v", decision)
	}
}

func TestEvaluateMissingAndNonGitDirectoriesFailClosed(t *testing.T) {
	cfg := &config.Config{CaptureScope: config.CaptureScopeApproved}
	if decision := Evaluate(cfg, ""); decision.Allowed || decision.Reason != SkipMissingWorkingDirectory {
		t.Fatalf("missing cwd decision = %#v", decision)
	}
	if decision := Evaluate(cfg, t.TempDir()); decision.Allowed || decision.Reason != SkipNonGitDirectory {
		t.Fatalf("non-Git decision = %#v", decision)
	}
}

func TestEvaluateGitWorktree(t *testing.T) {
	root := initRepository(t, "main")
	worktree := filepath.Join(t.TempDir(), "worktree")
	runGit(t, root, "worktree", "add", "-b", "feature", worktree)
	cfg := &config.Config{CaptureScope: config.CaptureScopeRepo, RepositoryRoot: worktree}
	if decision := Evaluate(cfg, worktree); !decision.Allowed {
		t.Fatalf("worktree was not treated as a repository root: %#v", decision)
	}
}

func initRepository(t *testing.T, name string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init", "--quiet")
	runGit(t, root, "config", "user.email", "test@example.invalid")
	runGit(t, root, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "README")
	runGit(t, root, "commit", "--quiet", "-m", "initial")
	return root
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}
