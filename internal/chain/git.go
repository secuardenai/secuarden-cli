package chain

import (
	"fmt"
	"os/exec"
	"strings"
)

func git(root string, args ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	out, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func resolveRange(root, base, baseRef, head string) (string, string, error) {
	if head == "" {
		head = "HEAD"
	}
	resolvedHead, err := git(root, "rev-parse", "--verify", head+"^{commit}")
	if err != nil {
		return "", "", fmt.Errorf("resolve head: %w", err)
	}
	var resolvedBase string
	switch {
	case base != "" && baseRef != "":
		return "", "", fmt.Errorf("pass either --base or --base-ref")
	case baseRef != "":
		resolvedBase, err = git(root, "merge-base", resolvedHead, baseRef)
		if err != nil {
			return "", "", fmt.Errorf("resolve merge base: %w", err)
		}
	case base != "":
		resolvedBase, err = git(root, "rev-parse", "--verify", base+"^{commit}")
		if err != nil {
			return "", "", fmt.Errorf("resolve base: %w", err)
		}
	default:
		return "", "", fmt.Errorf("a --base or --base-ref is required")
	}
	return resolvedBase, resolvedHead, nil
}

type commitTouch struct {
	ID      string
	Subject string
}

// commitsTouching maps a path to the newest commit in base..head that changes it.
func commitsTouching(root, base, head string) (map[string]commitTouch, error) {
	if base == head {
		return map[string]commitTouch{}, nil
	}
	command := exec.Command("git", "-C", root, "log", "--name-only", "--pretty=format:%H%x1f%s", base+".."+head)
	out, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("read commits: %w", err)
	}
	touches := map[string]commitTouch{}
	var current commitTouch
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if hash, subject, ok := strings.Cut(line, "\x1f"); ok {
			current = commitTouch{ID: hash, Subject: subject}
			continue
		}
		if current.ID == "" {
			continue
		}
		if _, seen := touches[line]; seen {
			continue
		}
		touches[line] = current
	}
	return touches, nil
}
