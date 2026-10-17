// Package changeledger records a Git revision independently of agent capture.
package changeledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const ContractVersion = "changeledger/v1"

// Observation is a directly observed Git fact. Value is an object ID or ref.
type Observation struct {
	Version       string `json:"version"`
	Name          string `json:"name"`
	Value         string `json:"value"`
	Scope         string `json:"scope"` // revision or context
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
}

// CaptureGap identifies Git data that could not be observed.
type CaptureGap struct {
	Version       string `json:"version"`
	Code          string `json:"code"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
}

type ChangedPath struct {
	Status        string `json:"status"`
	Path          string `json:"path"`
	OldPath       string `json:"old_path,omitempty"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
}

// InferredLink is a relationship inferred from observed facts, not a Git fact.
type InferredLink struct {
	Version       string `json:"version"`
	Kind          string `json:"kind"`
	From          string `json:"from"`
	To            string `json:"to"`
	Method        string `json:"method"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
}

// Change describes exactly one base-to-head Git revision. WorktreeDirty is
// contextual evidence and is deliberately excluded from the digest.
type Change struct {
	Version       string         `json:"version"`
	Digest        string         `json:"digest,omitempty"`
	Status        string         `json:"status"`
	Repository    string         `json:"repository"`
	BaseCommit    string         `json:"base_commit,omitempty"`
	BaseTree      string         `json:"base_tree,omitempty"`
	HeadCommit    string         `json:"head_commit,omitempty"`
	HeadTree      string         `json:"head_tree,omitempty"`
	ChangedPaths  []ChangedPath  `json:"changed_paths"`
	Observations  []Observation  `json:"observations"`
	InferredLinks []InferredLink `json:"inferred_links"`
	CaptureGaps   []CaptureGap   `json:"capture_gaps"`
	WorktreeDirty *bool          `json:"worktree_dirty,omitempty"`
}

// Receipt confirms storage of a canonical change in the separate ledger DB.
type Receipt struct {
	Version      string `json:"version"`
	ChangeDigest string `json:"change_digest"`
	StoredAt     string `json:"stored_at"`
	Database     string `json:"database"`
}

func (c *Change) setDigest() error {
	// The projection and slice ordering are part of v1's digest contract.
	type canonicalPath struct {
		Status  string `json:"status"`
		Path    string `json:"path"`
		OldPath string `json:"old_path,omitempty"`
	}
	paths := make([]canonicalPath, 0, len(c.ChangedPaths))
	for _, path := range c.ChangedPaths {
		paths = append(paths, canonicalPath{path.Status, path.Path, path.OldPath})
	}
	projection := struct {
		Version, Repository, BaseCommit, BaseTree, HeadCommit, HeadTree string
		ChangedPaths                                                    []canonicalPath
	}{c.Version, c.Repository, c.BaseCommit, c.BaseTree, c.HeadCommit, c.HeadTree, paths}
	b, err := json.Marshal(projection)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	c.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return nil
}
