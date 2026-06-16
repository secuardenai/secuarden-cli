package identity

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
)

// Developer holds identity fields captured from git config and OS.
type Developer struct {
	Name      string
	Email     string
	OSUser    string
	MachineID string
	GitBranch string
	GitRepo   string
}

var (
	cached   *Developer
	cacheOnce sync.Once
)

// Capture returns the developer identity. It is cached after the first call.
func Capture() *Developer {
	cacheOnce.Do(func() {
		cached = capture()
	})
	return cached
}

// CaptureWithDir captures identity resolving git context from the given directory.
// Unlike Capture(), this is not cached so it picks up the right repo.
func CaptureWithDir(dir string) *Developer {
	d := &Developer{}
	d.Name = gitConfig("user.name", dir)
	d.Email = gitConfig("user.email", dir)
	d.OSUser = osUsername()
	d.MachineID = machineID()
	d.GitBranch = gitBranch(dir)
	d.GitRepo = gitRemote(dir)
	return d
}

func capture() *Developer {
	d := &Developer{}
	d.Name = gitConfig("user.name", "")
	d.Email = gitConfig("user.email", "")
	d.OSUser = osUsername()
	d.MachineID = machineID()
	return d
}

func gitConfig(key, dir string) string {
	args := []string{"config", key}
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func gitBranch(dir string) string {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func gitRemote(dir string) string {
	cmd := exec.Command("git", "remote", "get-url", "origin")
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func osUsername() string {
	u, err := user.Current()
	if err != nil {
		return os.Getenv("USER")
	}
	return u.Username
}

func machineID() string {
	hostname, _ := os.Hostname()
	raw := fmt.Sprintf("%s:%s:%s", hostname, runtime.GOOS, runtime.GOARCH)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum[:8])
}
