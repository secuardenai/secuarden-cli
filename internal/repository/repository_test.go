package repository

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func initGitRepo(t *testing.T, path, remote string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "init", "--quiet", path)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "GIT_CONFIG_NOSYSTEM=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if remote != "" {
		cmd = exec.Command("git", "-C", path, "remote", "add", "origin", remote)
		cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "GIT_CONFIG_NOSYSTEM=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git remote add: %v: %s", err, output)
		}
	}
	return path
}

func TestNormalizeRemoteEquivalentSSHAndHTTPS(t *testing.T) {
	values := []string{
		"git@github.com:Example/verifyflow.git",
		"ssh://git@github.com/Example/verifyflow.git",
		"https://github.com/Example/verifyflow.git",
	}
	for _, value := range values {
		canonical, name, err := NormalizeRemote(value)
		if err != nil {
			t.Fatalf("NormalizeRemote(%q): %v", value, err)
		}
		if canonical != "github.com/Example/verifyflow" || name != "verifyflow" {
			t.Errorf("NormalizeRemote(%q) = %q, %q", value, canonical, name)
		}
	}
}

func TestResolvePathUsesRemoteAndFallsBackToRoot(t *testing.T) {
	root := initGitRepo(t, filepath.Join(t.TempDir(), "remote-repo"), "git@github.com:Example/verifyflow.git")
	subdir := filepath.Join(root, "nested")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := ResolvePath(subdir)
	if err != nil {
		t.Fatal(err)
	}
	resolvedRoot, _ := filepath.EvalSymlinks(root)
	if got.Canonical != "github.com/Example/verifyflow" || got.Root != resolvedRoot || !got.RootValid {
		t.Fatalf("unexpected remote identity: %#v", got)
	}

	localRoot := initGitRepo(t, filepath.Join(t.TempDir(), "local-repo"), "")
	localRoot, _ = filepath.EvalSymlinks(localRoot)
	got, err = ResolvePath(localRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got.Canonical != "local:"+filepath.ToSlash(localRoot) || !got.RootValid {
		t.Fatalf("unexpected local identity: %#v", got)
	}
}

func TestResolveIdentityOwnerRepoShortNameAndAmbiguity(t *testing.T) {
	groups := []Group{
		{Identity: Identity{Canonical: "github.com/acme/api", Name: "api"}},
		{Identity: Identity{Canonical: "gitlab.com/other/api", Name: "api"}},
		{Identity: Identity{Canonical: "github.com/acme/web", Name: "web"}},
	}
	got, err := ResolveIdentity("acme/web", groups)
	if err != nil || got.Canonical != "github.com/acme/web" {
		t.Fatalf("owner/repo resolution = %#v, %v", got, err)
	}
	if _, err := ResolveIdentity("api", groups); err == nil || !strings.Contains(err.Error(), "ambiguous") || !strings.Contains(err.Error(), "github.com/acme/api") {
		t.Fatalf("expected actionable ambiguity error, got %v", err)
	}
	got, err = ResolveIdentity("https://github.com/new/empty.git", groups)
	if err != nil || got.Canonical != "github.com/new/empty" {
		t.Fatalf("explicit empty remote resolution = %#v, %v", got, err)
	}
}

func TestFormatPathRepositoryRelativeAndAbsolute(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "project")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := Identity{Canonical: "github.com/acme/project", Name: "project", Root: root, RootValid: true}
	stored := filepath.Join(root, "verifyflow", "api.py")

	got := FormatPath(stored, repo, parent, false, false)
	if got.Display != "verifyflow/api.py" || got.External || got.Original != stored {
		t.Fatalf("relative display = %#v", got)
	}
	got = FormatPath(stored, repo, parent, false, true)
	if got.Display != "project/verifyflow/api.py" {
		t.Fatalf("all-repos display = %#v", got)
	}
	got = FormatPath(stored, repo, parent, true, true)
	if got.Display != stored || got.External {
		t.Fatalf("absolute display = %#v", got)
	}
}

func TestFormatPathExternalHomeCollisionAndExistingRelative(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "project")
	home := filepath.Join(parent, "home")
	repo := Identity{Canonical: "local:" + root, Name: "project", Root: root, RootValid: true}
	for _, path := range []string{root, home, filepath.Join(parent, "project-old")} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	collision := FormatPath(filepath.Join(parent, "project-old", "file.go"), repo, home, false, false)
	if !collision.External || collision.Display != filepath.Join(parent, "project-old", "file.go") {
		t.Fatalf("prefix collision treated as internal: %#v", collision)
	}
	homePath := FormatPath(filepath.Join(home, "Library", "settings.json"), repo, home, false, false)
	if !homePath.External || homePath.Display != "~/Library/settings.json" {
		t.Fatalf("home path display = %#v", homePath)
	}
	relative := FormatPath("verifyflow/../verifyflow/store.py", repo, home, false, true)
	if !relative.External || relative.Display != "verifyflow/store.py" {
		t.Fatalf("stored relative path display = %#v", relative)
	}
}

func TestGroupCapturedKeepsUnknownSessions(t *testing.T) {
	groups := GroupCaptured([]CapturedRef{{SessionID: "session-2"}, {SessionID: "session-1"}})
	if len(groups) != 1 || groups[0].Identity.Canonical != "unknown" || strings.Join(groups[0].SessionIDs, ",") != "session-1,session-2" {
		t.Fatalf("unexpected unknown grouping: %#v", groups)
	}
}
