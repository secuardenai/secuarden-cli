package capture

import (
	"path/filepath"

	"github.com/secuardenai/secuarden-cli/internal/events"
	"github.com/secuardenai/secuarden-cli/internal/repository"
	"github.com/secuardenai/secuarden-cli/internal/storage"
)

func addCheckpoint(db *storage.DB, e *events.Event) {
	switch e.HookPhase {
	case events.HookPhaseSessionStart, events.HookPhaseSessionEnd, events.HookPhasePre, events.HookPhasePost, events.HookPhaseCheckpoint:
	default:
		return
	}
	baseline, previous, err := db.CheckpointContext(e.SessionID)
	c := repository.CaptureCheckpoint(e.WorkingDirectory, e.HookPhase)
	e.RepositoryCheckpoint = c
	if previous != nil {
		c.PreviousSequence = previous.Sequence
	}
	reason := func(r string) {
		c.Reasons = appendUnique(c.Reasons, r)
		if c.Status == "complete" {
			c.Status = "partial"
		}
	}
	if err != nil {
		reason("checkpoint_history_unavailable")
	}
	first := e.HookPhase == events.HookPhaseSessionStart && previous == nil && err == nil
	if !first && (baseline == nil || baseline.RepositoryCheckpoint == nil) {
		reason("baseline_absent")
	}
	if baseline != nil && baseline.RepositoryCheckpoint != nil && (baseline.RepositoryCheckpoint.Status != "complete" || baseline.RepositoryCheckpoint.Root != c.Root) {
		reason("baseline_unavailable")
	}
	var before *repository.Checkpoint
	if previous != nil {
		before = previous.RepositoryCheckpoint
	}
	if e.HookPhase == events.HookPhasePost && (before == nil || previous.HookPhase != events.HookPhasePre || e.InvocationID == "" || previous.InvocationID != e.InvocationID || previous.ToolName != e.ToolName) {
		reason("pre_checkpoint_absent")
	}
	old := map[string]repository.FileState{}
	if before != nil && before.Root == c.Root {
		for _, f := range before.Files {
			old[f.Path] = f
		}
	}
	base := map[string]repository.FileState{}
	if baseline != nil && baseline.RepositoryCheckpoint != nil && baseline.RepositoryCheckpoint.Root == c.Root {
		for _, f := range baseline.RepositoryCheckpoint.Files {
			base[f.Path] = f
		}
	}
	// Include paths removed from the index or untracked set since the last scan.
	seen := map[string]bool{}
	for _, f := range c.Files {
		seen[f.Path] = true
	}
	enumerated := c.Status != "failed"
	for _, r := range c.Reasons {
		if r == "status_failed" || r == "index_failed" {
			enumerated = false
		}
	}
	if before != nil && before.Root == c.Root && enumerated {
		for _, f := range before.Files {
			if !seen[f.Path] {
				c.Files = append(c.Files, repository.FileState{Path: f.Path, Status: "absent_from_capture_set", Sensitive: f.Sensitive, ObservedAt: c.FinishedAt, Attribution: "human_or_unattributed"})
			}
		}
	}
	targets := map[string]bool{}
	add := func(path string) {
		if path == "" {
			return
		}
		full := resolveFilePath(e.WorkingDirectory, path)
		if parent, err := filepath.EvalSymlinks(filepath.Dir(full)); err == nil {
			full = filepath.Join(parent, filepath.Base(full))
		}
		rel, err := filepath.Rel(c.Root, full)
		if err == nil {
			targets[filepath.ToSlash(rel)] = true
		}
	}
	add(e.FilePath)
	for _, f := range e.AffectedFiles {
		add(f.Path)
	}
	paired := c.Status == "complete" && before != nil && before.Status == "complete" && before.Root == c.Root && before.Head == c.Head && previous.HookPhase == events.HookPhasePre && e.HookPhase == events.HookPhasePost && e.InvocationID != "" && previous.InvocationID == e.InvocationID && previous.ToolName == e.ToolName && e.Outcome == events.ResultSuccess && (e.ActionType == events.ActionFileWrite || e.ActionType == events.ActionFileDelete)
	for i := range c.Files {
		f := &c.Files[i]
		b := base[f.Path]
		p, exists := old[f.Path]
		f.PreExisting = b.PreExisting
		f.Attribution = "human_or_unattributed"
		if first {
			f.PreExisting = f.Staged != "" || f.Unstaged != "" || f.Untracked
			f.Attribution = "unchanged"
			if f.PreExisting {
				f.Attribution = "pre_existing"
			}
			continue
		}
		if exists && f.Digest == p.Digest && f.Status == p.Status && f.Index == p.Index && f.Staged == p.Staged && f.Unstaged == p.Unstaged && f.Untracked == p.Untracked {
			f.Attribution = p.Attribution
			f.BeforeDigest = p.BeforeDigest
			continue
		}
		f.BeforeDigest = p.Digest
		// Only the delta within a successful explicit file operation is associated
		// with an agent. Shell/MCP side effects and concurrent edits remain unknown.
		if paired && targets[f.Path] && (f.Digest != p.Digest || f.Status != p.Status) && (f.Status == "present" || f.Status == "deleted") && (!exists || p.Status == "present" || p.Status == "deleted") {
			f.Attribution = "agent_associated"
		}
	}
	if c.Status != "complete" {
		e.Completeness.State = "partial"
		e.Completeness.Reasons = appendUnique(e.Completeness.Reasons, "repository_checkpoint_incomplete")
	}
}
