package changeledger

import (
	"context"
	"os"
	"os/exec"
)

// diffTrees reads the selected repository's object database through a temporary
// bare repository. This excludes worktree, index, info/attributes, and user
// configuration from rename detection. Only attributes committed in head apply.
// The temporary repository has no refs and writes no objects to the source.
func diffTrees(ctx context.Context, git func(...string) (string, error), env []string, base, head string) (string, error) {
	objects, err := git("rev-parse", "--path-format=absolute", "--git-path", "objects")
	if err != nil {
		return "", err
	}
	format, err := git("rev-parse", "--show-object-format")
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "secuarden-ledger-diff-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	env = append(append([]string(nil), env...),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_ATTR_NOSYSTEM=1")
	init := exec.CommandContext(ctx, "git", "init", "--bare", "--quiet", "--template=", "--object-format="+format, dir)
	init.Env = env
	if _, err := init.Output(); err != nil {
		return "", err
	}
	// The explicit attribute source also prevents an empty bare worktree from
	// dropping the selected revision's committed attributes. Unsupported Git
	// versions fail with a capture gap rather than guessing a path list.
	command := exec.CommandContext(ctx, "git", "-C", dir, "--no-pager", "--attr-source="+head,
		"-c", "core.attributesFile="+os.DevNull,
		"diff", "--name-status", "-z", "--no-ext-diff", "--no-textconv",
		"--find-renames=50%", "-l0", "--ignore-submodules=none", base, head, "--")
	command.Env = append(env, "GIT_OBJECT_DIRECTORY="+objects)
	output, err := command.Output()
	return string(output), err
}
