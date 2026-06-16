package capture

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestComputeFileHash(t *testing.T) {
	t.Run("empty path returns empty string", func(t *testing.T) {
		if got := computeFileHash(""); got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("nonexistent file returns empty string", func(t *testing.T) {
		if got := computeFileHash("/nonexistent/path/file.txt"); got != "" {
			t.Errorf("expected empty for missing file, got %q", got)
		}
	})

	t.Run("real file returns correct SHA-256", func(t *testing.T) {
		content := []byte("hello secuarden\n")
		f, err := os.CreateTemp(t.TempDir(), "*.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(content); err != nil {
			t.Fatal(err)
		}
		f.Close()

		want := fmt.Sprintf("%x", sha256.Sum256(content))
		got := computeFileHash(f.Name())
		if got != want {
			t.Errorf("hash mismatch: got %q, want %q", got, want)
		}
	})

	t.Run("sensitive file still gets hashed", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".env")
		if err := os.WriteFile(path, []byte("SECRET=abc"), 0600); err != nil {
			t.Fatal(err)
		}
		got := computeFileHash(path)
		if got == "" {
			t.Error("expected non-empty hash for sensitive file — content_hash is stored even for sensitive files per spec")
		}
	})
}
