// Package policy implements the deliberately bounded v0.1 local policy engine.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"
)

const MaxBytes = 2 * 1024 * 1024

type Policy struct {
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	Language           string   `json:"language"`
	SecurityDecorators []string `json:"security_decorators"`
	RouteDecorators    []string `json:"route_decorators"`
}

type Bundle struct {
	Version  string   `json:"version"`
	Policies []Policy `json:"policies"`
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)
var policyID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func (p Policy) Validate() error {
	if !policyID.MatchString(p.ID) {
		return fmt.Errorf("id must be 1–128 letters, digits, dots, underscores or hyphens")
	}
	if p.Kind != "protect_route_security_decorators" || p.Language != "python" {
		return fmt.Errorf("supported capability: protect_route_security_decorators for python")
	}
	for name, values := range map[string][]string{"security_decorators": p.SecurityDecorators, "route_decorators": p.RouteDecorators} {
		if len(values) == 0 || len(values) > 64 {
			return fmt.Errorf("%s requires 1–64 decorator names", name)
		}
		for _, value := range values {
			if !identifier.MatchString(value) {
				return fmt.Errorf("%s must contain dotted Python identifiers", name)
			}
		}
	}
	return nil
}

func strict(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected one JSON document")
	}
	return nil
}

func readBounded(path string) ([]byte, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("expected regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("expected regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", MaxBytes)
	}
	return b, nil
}

// ParseImport rejects malformed envelopes, but reports invalid entries separately.
func ParseImport(data []byte) ([]Policy, []string, error) {
	if len(data) > MaxBytes {
		return nil, nil, fmt.Errorf("policy file too large")
	}
	var raw struct {
		Version  string            `json:"version"`
		Policies []json.RawMessage `json:"policies"`
	}
	if err := strict(data, &raw); err != nil {
		return nil, nil, err
	}
	if raw.Version != "0.1" || len(raw.Policies) == 0 {
		return nil, nil, fmt.Errorf("version must be 0.1 and policies must be a nonempty array")
	}
	var valid []Policy
	var rejected []string
	seen := map[string]bool{}
	for i, entry := range raw.Policies {
		var p Policy
		err := strict(entry, &p)
		if err == nil {
			err = p.Validate()
		}
		if err == nil && seen[p.ID] {
			err = fmt.Errorf("duplicate policy id")
		}
		if err != nil {
			rejected = append(rejected, fmt.Sprintf("entry %d: %v", i+1, err))
			continue
		}
		seen[p.ID] = true
		valid = append(valid, p)
	}
	return valid, rejected, nil
}

func StorePath() (string, error) {
	home, err := os.UserHomeDir()
	return filepath.Join(home, ".secuarden", "policies.json"), err
}

func Load() ([]Policy, error) {
	path, err := StorePath()
	if err != nil {
		return nil, err
	}
	data, err := readBounded(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b Bundle
	if err := strict(data, &b); err != nil {
		return nil, fmt.Errorf("invalid policy store: %w", err)
	}
	if b.Version != "0.1" {
		return nil, fmt.Errorf("unsupported policy store version")
	}
	seen := map[string]bool{}
	for _, p := range b.Policies {
		if err := p.Validate(); err != nil {
			return nil, err
		}
		if seen[p.ID] {
			return nil, fmt.Errorf("duplicate stored policy")
		}
		seen[p.ID] = true
	}
	return b.Policies, nil
}

// Import serializes concurrent imports and atomically replaces the store.
// Existing IDs are skipped: importing cannot silently weaken an active rule.
func Import(path string) (int, []string, error) {
	data, err := readBounded(path)
	if err != nil {
		return 0, nil, err
	}
	valid, rejected, err := ParseImport(data)
	if err != nil {
		return 0, nil, err
	}
	if len(valid) == 0 {
		return 0, rejected, nil
	}
	if err := CheckRuntime(); err != nil {
		return 0, rejected, err
	}
	dest, err := StorePath()
	if err != nil {
		return 0, rejected, err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return 0, rejected, err
	}
	lock, err := os.OpenFile(dest+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return 0, rejected, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return 0, rejected, err
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	current, err := Load()
	if err != nil {
		return 0, rejected, err
	}
	seen := map[string]bool{}
	for _, p := range current {
		seen[p.ID] = true
	}
	count := 0
	for _, p := range valid {
		if seen[p.ID] {
			rejected = append(rejected, p.ID+": already active")
			continue
		}
		current = append(current, p)
		count++
	}
	if count == 0 {
		return 0, rejected, nil
	}
	encoded, err := json.MarshalIndent(Bundle{Version: "0.1", Policies: current}, "", "  ")
	if err != nil {
		return 0, rejected, err
	}
	if len(encoded) > MaxBytes {
		return 0, rejected, fmt.Errorf("policy store exceeds size limit")
	}
	f, err := os.CreateTemp(filepath.Dir(dest), "policies-*.tmp")
	if err != nil {
		return 0, rejected, err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(encoded)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return 0, rejected, err
	}
	if err = os.Rename(f.Name(), dest); err != nil {
		return 0, rejected, err
	}
	return count, rejected, nil
}
