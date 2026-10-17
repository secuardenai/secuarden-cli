package capture

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secuardenai/secuarden-cli/internal/events"
)

func TestHookInputSizeBoundary(t *testing.T) {
	for _, agent := range []struct{ name, provider string }{{"claude-code", "anthropic"}, {"codex", "openai"}} {
		for _, size := range []int{maxStdinBytes - 1, maxStdinBytes, maxStdinBytes + 1, maxStdinBytes + 1024} {
			t.Run(fmt.Sprintf("%s/%d", agent.name, size), func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				input, err := os.CreateTemp(t.TempDir(), "hook-*.json")
				if err != nil {
					t.Fatal(err)
				}
				defer input.Close()
				// A valid JSON prefix with whitespace: silent truncation would still parse.
				payload := "{}" + strings.Repeat(" ", size-2)
				if _, err := input.WriteString(payload); err != nil {
					t.Fatal(err)
				}
				if _, err := input.Seek(0, io.SeekStart); err != nil {
					t.Fatal(err)
				}
				previous := os.Stdin
				os.Stdin = input
				defer func() { os.Stdin = previous }()
				parsed := false
				stop := errors.New("stop before capture side effects")
				err = handleWithParser("post-tool-use", "test", agent.name, agent.provider, func(data []byte) (*events.RawHookInput, error) {
					parsed = true
					if string(data) != payload {
						t.Error("parser received truncated or modified payload")
					}
					return nil, stop
				})
				if size > maxStdinBytes {
					want := fmt.Sprintf("hook input exceeds %d bytes", maxStdinBytes)
					if parsed || err == nil || err.Error() != want {
						t.Fatalf("oversized input: parsed=%v err=%v", parsed, err)
					}
					position, seekErr := input.Seek(0, io.SeekCurrent)
					if seekErr != nil || position != int64(maxStdinBytes+1) {
						t.Fatalf("unbounded read: position=%d err=%v", position, seekErr)
					}
				} else if !parsed || !errors.Is(err, stop) {
					t.Fatalf("in-bounds input did not reach parser: parsed=%v err=%v", parsed, err)
				}
				if _, err := os.Stat(filepath.Join(home, ".secuarden")); !os.IsNotExist(err) {
					t.Fatalf("unexpected capture side effects: %v", err)
				}
			})
		}
	}
}
