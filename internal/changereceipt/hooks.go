package changereceipt

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/secuardenai/secuarden-cli/internal/repository"
)

const hookMarker = "# secuarden receipt pre-push v1"

func Git(path string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "git", append([]string{"-C", path}, args...)...)
	env := []string{}
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		if strings.HasPrefix(k, "GIT_") {
			continue
		}
		env = append(env, v)
	}
	c.Env = append(env, "GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1", "GIT_OPTIONAL_LOCKS=0")
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("Git query unavailable")
	}
	return strings.TrimSpace(string(out)), nil
}
func HookPath(root string) (string, error) {
	if custom, _ := Git(root, "config", "--get", "core.hooksPath"); custom != "" {
		return "", fmt.Errorf("custom core.hooksPath is configured; automatic receipt setup requires repository-local default hooks")
	}
	path, err := Git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "hooks", "pre-push"), nil
}
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func ConfigureHook(root, binary, mode string) error {
	path, err := HookPath(root)
	if err != nil {
		if mode == "explicit" {
			return nil
		}
		return err
	}
	raw, readErr := os.ReadFile(path)
	managed := bytes.Contains(raw, []byte(hookMarker))
	backup := path + ".secuarden-original"
	if mode == "explicit" {
		if !managed {
			return nil
		}
		if _, err := os.Stat(backup); err == nil {
			return os.Rename(backup, path)
		}
		return os.Remove(path)
	}
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if !managed && readErr == nil {
		if _, err := os.Lstat(backup); !os.IsNotExist(err) {
			return fmt.Errorf("existing Secuarden hook backup requires manual review")
		}
		if err := os.Rename(path, backup); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	script := "#!/bin/sh\n" + hookMarker + "\nif [ -x " + quote(binary) + " ]; then\n  exec " + quote(binary) + " ledger receipt pre-push --repo . --original " + quote(backup) + " -- \"$@\"\nfi\necho 'Secuarden receipt capture unavailable: CLI executable missing' >&2\nif [ -x " + quote(backup) + " ]; then exec " + quote(backup) + " \"$@\"; fi\nexit 0\n"
	temp, err := os.CreateTemp(filepath.Dir(path), ".secuarden-pre-push-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err = temp.WriteString(script); err == nil {
		err = temp.Chmod(0700)
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil && !managed && readErr == nil {
		_ = os.Rename(backup, path)
	}
	return err
}

type RefUpdate struct{ LocalRef, Head, Destination, Previous string }

func ParseUpdates(input io.Reader) ([]RefUpdate, error) {
	s := bufio.NewScanner(io.LimitReader(input, 1024*1024+1))
	result := []RefUpdate{}
	total := 0
	for s.Scan() {
		total += len(s.Bytes()) + 1
		if total > 1024*1024 {
			return nil, fmt.Errorf("push input exceeds limit")
		}
		f := strings.Fields(s.Text())
		if len(f) != 4 {
			return nil, fmt.Errorf("invalid push ref update")
		}
		for _, oid := range []string{f[1], f[3]} {
			if (len(oid) != 40 && len(oid) != 64) || strings.Trim(oid, "0123456789abcdef") != "" {
				return nil, fmt.Errorf("invalid push object ID")
			}
		}
		result = append(result, RefUpdate{f[0], f[1], f[2], f[3]})
	}
	return result, s.Err()
}
func GitHubName(raw string) (string, error) {
	canonical, _, err := repository.NormalizeRemote(raw)
	if err != nil || !strings.HasPrefix(canonical, "github.com/") {
		return "", fmt.Errorf("an unambiguous GitHub remote is required")
	}
	name := strings.TrimPrefix(canonical, "github.com/")
	if !repositoryName.MatchString(name) {
		return "", fmt.Errorf("invalid GitHub repository identity")
	}
	return name, nil
}
