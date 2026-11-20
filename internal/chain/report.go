// Package chain joins a captured prompt, edit, and posture finding to the
// commit that contains the edit. The result is a local checksum of that record.
package chain

import (
	"path/filepath"
	"strings"

	"github.com/secuardenai/secuarden-cli/internal/storage"
)

type Finding struct {
	Kind        string `json:"kind"`
	Explanation string `json:"explanation"`
}

type Entry struct {
	Path           string    `json:"path"`
	SessionID      string    `json:"session_id"`
	Prompt         string    `json:"prompt,omitempty"`
	PromptCaptured bool      `json:"prompt_captured"`
	Commit         string    `json:"commit,omitempty"`
	CommitSubject  string    `json:"commit_subject,omitempty"`
	Committed      bool      `json:"committed"`
	Before         string    `json:"before,omitempty"`
	After          string    `json:"after,omitempty"`
	Findings       []Finding `json:"findings,omitempty"`
}

type Report struct {
	Repository string  `json:"repository"`
	Base       string  `json:"base"`
	Head       string  `json:"head"`
	Integrity  string  `json:"integrity"`
	Entries    []Entry `json:"entries"`
}

// Build reads the local capture database and the commits between base and head.
// Integrity is "checksum": the developer who can edit the database can recompute it.
func Build(db *storage.DB, root, base, baseRef, head string) (*Report, error) {
	resolvedBase, resolvedHead, err := resolveRange(root, base, baseRef, head)
	if err != nil {
		return nil, err
	}
	touches, err := commitsTouching(root, resolvedBase, resolvedHead)
	if err != nil {
		return nil, err
	}
	edits, err := db.ListChainEdits()
	if err != nil {
		return nil, err
	}
	report := &Report{Repository: root, Base: resolvedBase, Head: resolvedHead, Integrity: "checksum", Entries: []Entry{}}
	for _, edit := range edits {
		rel, ok := repositoryPath(root, edit.WorkingDirectory, edit.Path)
		if !ok {
			continue
		}
		entry := Entry{
			Path: rel, SessionID: edit.SessionID, Prompt: edit.Intent,
			PromptCaptured: strings.TrimSpace(edit.Intent) != "",
			Before:         edit.Before, After: edit.After,
		}
		if touch, ok := touches[rel]; ok {
			entry.Commit = touch.ID
			entry.CommitSubject = touch.Subject
			entry.Committed = true
		}
		for _, finding := range edit.Findings {
			entry.Findings = append(entry.Findings, Finding{Kind: finding.Kind, Explanation: finding.Explanation})
		}
		report.Entries = append(report.Entries, entry)
	}
	return report, nil
}

func repositoryPath(root, cwd, file string) (string, bool) {
	if file == "" {
		return "", false
	}
	full := file
	if !filepath.IsAbs(full) {
		if cwd == "" {
			return "", false
		}
		full = filepath.Join(cwd, file)
	}
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}
