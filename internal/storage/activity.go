package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// EventFilter selects captured events. Filters are combined with AND.
type EventFilter struct {
	Limit            int
	ActionType       string
	SessionID        string
	Sensitive        bool
	Since            time.Time
	Until            time.Time
	SessionIDs       []string
	RestrictSessions bool
}

// StoredEvent is the privacy-safe event representation returned by activity
// queries. Every text field comes directly from the already-redacted database.
type StoredEvent struct {
	ID                   string   `json:"id"`
	SessionID            string   `json:"session_id"`
	Sequence             int      `json:"sequence"`
	Timestamp            string   `json:"timestamp"`
	AgentName            string   `json:"agent_name"`
	HookPhase            string   `json:"hook_phase"`
	ActionType           string   `json:"action_type"`
	ToolName             string   `json:"tool_name,omitempty"`
	ResultStatus         string   `json:"result_status,omitempty"`
	IsSensitive          bool     `json:"is_sensitive"`
	RedactedFields       []string `json:"redacted_fields"`
	FilePath             string   `json:"file_path,omitempty"`
	DiffStats            string   `json:"diff_stats,omitempty"`
	Command              string   `json:"command,omitempty"`
	ExitCode             *int     `json:"exit_code,omitempty"`
	CommandOutputPreview string   `json:"command_output_preview,omitempty"`
	MCPServer            string   `json:"mcp_server,omitempty"`
	MCPTool              string   `json:"mcp_tool,omitempty"`
	DurationMS           *int64   `json:"duration_ms,omitempty"`
	WorkingDirectory     string   `json:"working_directory,omitempty"`
	GitBranch            string   `json:"git_branch,omitempty"`
	DeveloperEmail       string   `json:"developer_email,omitempty"`
}

// QueryEvents returns the most recent matching events in chronological order.
// Timestamp, session, sequence, and ID ordering makes results deterministic.
func (d *DB) QueryEvents(filter EventFilter) ([]StoredEvent, error) {
	if filter.RestrictSessions && len(filter.SessionIDs) == 0 {
		return []StoredEvent{}, nil
	}
	where := []string{"1 = 1"}
	args := make([]interface{}, 0, 5)
	if filter.ActionType != "" {
		where = append(where, "action_type = ?")
		args = append(args, filter.ActionType)
	}
	if filter.SessionID != "" {
		where = append(where, "session_id = ?")
		args = append(args, filter.SessionID)
	}
	if filter.RestrictSessions {
		placeholders := make([]string, len(filter.SessionIDs))
		for i, sessionID := range filter.SessionIDs {
			placeholders[i] = "?"
			args = append(args, sessionID)
		}
		where = append(where, "session_id IN ("+strings.Join(placeholders, ",")+")")
	}
	if filter.Sensitive {
		where = append(where, "is_sensitive = 1")
	}
	if !filter.Since.IsZero() {
		where = append(where, "julianday(timestamp) >= julianday(?)")
		args = append(args, filter.Since.UTC().Format(time.RFC3339Nano))
	}
	if !filter.Until.IsZero() {
		where = append(where, "julianday(timestamp) < julianday(?)")
		args = append(args, filter.Until.UTC().Format(time.RFC3339Nano))
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 20
	}
	args = append(args, limit)
	query := `
		SELECT id, session_id, sequence, timestamp, agent_name, hook_phase,
		       action_type, COALESCE(tool_name, ''), COALESCE(result_status, ''),
		       is_sensitive, COALESCE(redacted_fields, '[]'),
		       COALESCE(file_path, ''), COALESCE(diff_stats, ''),
		       COALESCE(command, ''), exit_code,
		       COALESCE(command_output_preview, ''),
		       COALESCE(mcp_server, ''), COALESCE(mcp_tool, ''), duration_ms,
		       COALESCE(report_working_directory, ''), COALESCE(git_branch, ''),
		       COALESCE(developer_email, '')
		FROM (
			SELECT events.*,
			       COALESCE(events.working_directory,
			           (SELECT sessions.working_directory FROM sessions WHERE sessions.id = events.session_id),
			           '') AS report_working_directory
			FROM events WHERE ` + strings.Join(where, " AND ") + `
			ORDER BY julianday(timestamp) DESC, session_id DESC, sequence DESC, id DESC
			LIMIT ?
		)
		ORDER BY julianday(timestamp) ASC, session_id ASC, sequence ASC, id ASC`

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	result := make([]StoredEvent, 0)
	for rows.Next() {
		var e StoredEvent
		var sensitive int
		var redacted string
		var exitCode sql.NullInt64
		var duration sql.NullInt64
		if err := rows.Scan(
			&e.ID, &e.SessionID, &e.Sequence, &e.Timestamp, &e.AgentName,
			&e.HookPhase, &e.ActionType, &e.ToolName, &e.ResultStatus,
			&sensitive, &redacted, &e.FilePath, &e.DiffStats, &e.Command,
			&exitCode, &e.CommandOutputPreview, &e.MCPServer, &e.MCPTool,
			&duration, &e.WorkingDirectory, &e.GitBranch, &e.DeveloperEmail,
		); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		e.IsSensitive = sensitive == 1
		e.RedactedFields = make([]string, 0)
		_ = json.Unmarshal([]byte(redacted), &e.RedactedFields)
		if exitCode.Valid {
			v := int(exitCode.Int64)
			e.ExitCode = &v
		}
		if duration.Valid {
			v := duration.Int64
			e.DurationMS = &v
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

// AttentionFinding is a reliable finding derived from explicit capture data.
type AttentionFinding struct {
	Timestamp   string `json:"timestamp"`
	SessionID   string `json:"session_id"`
	Kind        string `json:"kind"`
	ActionType  string `json:"action_type"`
	Summary     string `json:"summary"`
	Status      string `json:"status,omitempty"`
	ExitCode    *int   `json:"exit_code,omitempty"`
	IsSensitive bool   `json:"is_sensitive"`
}

func findingsForEvent(e StoredEvent) []AttentionFinding {
	f := AttentionFinding{
		Timestamp: e.Timestamp, SessionID: e.SessionID, ActionType: e.ActionType,
		Summary: eventSubject(e), Status: e.ResultStatus, ExitCode: e.ExitCode,
		IsSensitive: e.IsSensitive,
	}
	findings := make([]AttentionFinding, 0, 2)
	// A pre-tool event records an attempted access, not proof that the tool ran.
	// Only label a sensitive access when capture reached a non-pre phase.
	if e.IsSensitive && e.HookPhase != "pre" {
		sensitive := f
		sensitive.Kind = "sensitive_access"
		findings = append(findings, sensitive)
	}
	if e.ResultStatus == "blocked" {
		f.Kind = "blocked_action"
		return append(findings, f)
	}
	if e.ResultStatus == "rejected" {
		f.Kind = "rejected_action"
		return append(findings, f)
	}
	failedStatus := e.ResultStatus == "error" || e.ResultStatus == "failed" || e.ResultStatus == "failure"
	nonzeroExit := e.ExitCode != nil && *e.ExitCode != 0
	if e.ActionType == "command_exec" && (nonzeroExit || failedStatus) {
		f.Kind = "failed_command"
		return append(findings, f)
	}
	if failedStatus || nonzeroExit {
		f.Kind = "failed_action"
		return append(findings, f)
	}
	return findings
}

func eventSubject(e StoredEvent) string {
	for _, value := range []string{e.FilePath, e.Command, mcpName(e), e.ToolName, e.ActionType} {
		if value != "" {
			return value
		}
	}
	return "captured action"
}

func mcpName(e StoredEvent) string {
	if e.MCPServer != "" && e.MCPTool != "" {
		return e.MCPServer + "/" + e.MCPTool
	}
	return e.MCPTool
}

// ActivityCounts contains aggregate counts for a period or session.
type ActivityCounts struct {
	Sessions               int `json:"sessions"`
	Actions                int `json:"actions"`
	FilesRead              int `json:"files_read"`
	FilesChanged           int `json:"files_changed"`
	RepositoryFilesRead    int `json:"repository_files_read"`
	RepositoryFilesChanged int `json:"repository_files_changed"`
	ExternalFilesRead      int `json:"external_files_read"`
	ExternalFilesChanged   int `json:"external_files_changed"`
	Commands               int `json:"commands"`
	MCPCalls               int `json:"mcp_calls"`
	SensitiveAccesses      int `json:"sensitive_accesses"`
}

// RecentSession is a compact session summary for status.
type RecentSession struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Agent        string `json:"agent"`
	StartedAt    string `json:"started_at"`
	EndedAt      string `json:"ended_at,omitempty"`
	EventCount   int    `json:"event_count"`
	FilesChanged int    `json:"files_changed"`
	Warnings     int    `json:"warnings"`
}

// StatusSummary is the captured-data portion of the status presentation.
type StatusSummary struct {
	Agent          string             `json:"agent"`
	Today          ActivityCounts     `json:"today"`
	Attention      []AttentionFinding `json:"attention"`
	RecentSessions []RecentSession    `json:"recent_sessions"`
}

// GetStatusSummary aggregates activity in [dayStart, dayEnd).
func (d *DB) GetStatusSummary(dayStart, dayEnd time.Time, recentLimit int) (*StatusSummary, error) {
	all, err := d.QueryEvents(EventFilter{Since: dayStart, Until: dayEnd, Limit: 1000000})
	if err != nil {
		return nil, err
	}
	s := &StatusSummary{
		Attention: make([]AttentionFinding, 0), RecentSessions: make([]RecentSession, 0),
	}
	read, changed := map[string]struct{}{}, map[string]struct{}{}
	sessions := map[string]struct{}{}
	for _, e := range all {
		s.Today.Actions++
		sessions[e.SessionID] = struct{}{}
		if e.ActionType == "file_read" && e.FilePath != "" {
			read[e.FilePath] = struct{}{}
		}
		if (e.ActionType == "file_write" || e.ActionType == "file_delete") && e.FilePath != "" {
			changed[e.FilePath] = struct{}{}
		}
		if e.ActionType == "command_exec" && e.HookPhase != "pre" {
			s.Today.Commands++
		}
		if e.ActionType == "mcp_tool_use" && e.HookPhase != "pre" {
			s.Today.MCPCalls++
		}
		if e.IsSensitive && e.HookPhase != "pre" {
			s.Today.SensitiveAccesses++
		}
		s.Attention = append(s.Attention, findingsForEvent(e)...)
	}
	s.Today.Sessions = len(sessions)
	s.Today.FilesRead = len(read)
	s.Today.FilesChanged = len(changed)
	if len(s.Attention) > 10 {
		s.Attention = s.Attention[len(s.Attention)-10:]
	}

	if recentLimit <= 0 {
		recentLimit = 3
	}
	rows, err := d.db.Query(`
		SELECT s.id,
		       COALESCE(s.git_branch, ''), COALESCE(s.working_directory, ''), COALESCE(s.agent_name, ''),
		       s.started_at, COALESCE(s.ended_at, ''),
		       (SELECT COUNT(*) FROM events e WHERE e.session_id = s.id),
		       (SELECT COUNT(DISTINCT e.file_path) FROM events e
		        WHERE e.session_id = s.id AND e.action_type IN ('file_write', 'file_delete')
		          AND e.file_path IS NOT NULL AND e.file_path != ''),
		       (SELECT COUNT(*) FROM events e WHERE e.session_id = s.id AND
		          ((e.is_sensitive = 1 AND e.hook_phase != 'pre') OR e.result_status IN ('error','failed','failure','blocked','rejected')
		           OR (e.action_type = 'command_exec' AND e.exit_code IS NOT NULL AND e.exit_code != 0)))
		FROM sessions s
		ORDER BY s.started_at DESC, s.id DESC LIMIT ?`, recentLimit)
	if err != nil {
		return nil, fmt.Errorf("query recent sessions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var rs RecentSession
		var branch, workingDir string
		if err := rows.Scan(&rs.ID, &branch, &workingDir, &rs.Agent, &rs.StartedAt, &rs.EndedAt,
			&rs.EventCount, &rs.FilesChanged, &rs.Warnings); err != nil {
			return nil, fmt.Errorf("scan recent session: %w", err)
		}
		rs.Label = branch
		if rs.Label == "" {
			rs.Label = filepath.Base(filepath.Clean(workingDir))
		}
		if rs.Label == "." || rs.Label == string(filepath.Separator) || rs.Label == "" {
			rs.Label = rs.ID
		}
		if s.Agent == "" {
			s.Agent = rs.Agent
		}
		s.RecentSessions = append(s.RecentSessions, rs)
	}
	return s, rows.Err()
}

// CountByAction is a deterministic action count.
type CountByAction struct {
	ActionType string `json:"action_type"`
	Count      int    `json:"count"`
}

// CommandActivity records a command and its captured outcome.
type CommandActivity struct {
	Timestamp string `json:"timestamp"`
	Command   string `json:"command"`
	ExitCode  *int   `json:"exit_code,omitempty"`
	Status    string `json:"status,omitempty"`
}

// MCPActivity records an MCP tool invocation.
type MCPActivity struct {
	Timestamp string `json:"timestamp"`
	Server    string `json:"server,omitempty"`
	Tool      string `json:"tool"`
	Status    string `json:"status,omitempty"`
}

// SessionInvestigation is the complete local view of one session.
type SessionInvestigation struct {
	SessionID         string             `json:"session_id"`
	Agent             string             `json:"agent"`
	DeveloperName     string             `json:"developer_name,omitempty"`
	DeveloperEmail    string             `json:"developer_email,omitempty"`
	Repository        string             `json:"repository,omitempty"`
	WorkingDirectory  string             `json:"working_directory,omitempty"`
	Branch            string             `json:"branch,omitempty"`
	StartedAt         string             `json:"started_at"`
	EndedAt           string             `json:"ended_at,omitempty"`
	DurationSeconds   *int64             `json:"duration_seconds,omitempty"`
	EventCount        int                `json:"event_count"`
	CountsByAction    []CountByAction    `json:"counts_by_action"`
	FilesRead         []string           `json:"files_read"`
	FilesChanged      []string           `json:"files_changed"`
	Commands          []CommandActivity  `json:"commands"`
	MCPTools          []MCPActivity      `json:"mcp_tools"`
	SensitiveAccesses []StoredEvent      `json:"sensitive_accesses"`
	Attention         []AttentionFinding `json:"attention"`
}

// GetSessionInvestigation returns one session and its captured activity.
func (d *DB) GetSessionInvestigation(sessionID string) (*SessionInvestigation, error) {
	s := &SessionInvestigation{
		SessionID: sessionID, CountsByAction: make([]CountByAction, 0),
		FilesRead: make([]string, 0), FilesChanged: make([]string, 0),
		Commands: make([]CommandActivity, 0), MCPTools: make([]MCPActivity, 0),
		SensitiveAccesses: make([]StoredEvent, 0), Attention: make([]AttentionFinding, 0),
	}
	err := d.db.QueryRow(`
		SELECT agent_name, COALESCE(developer_name, ''), COALESCE(developer_email, ''),
		       COALESCE(git_repo_url, ''), COALESCE(working_directory, ''),
		       COALESCE(git_branch, ''), started_at, COALESCE(ended_at, '')
		FROM sessions WHERE id = ?`, sessionID).Scan(
		&s.Agent, &s.DeveloperName, &s.DeveloperEmail, &s.Repository,
		&s.WorkingDirectory, &s.Branch, &s.StartedAt, &s.EndedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	if s.Repository == "" {
		s.Repository = s.WorkingDirectory
	}
	if start, err := time.Parse(time.RFC3339Nano, s.StartedAt); err == nil && s.EndedAt != "" {
		if end, err := time.Parse(time.RFC3339Nano, s.EndedAt); err == nil && !end.Before(start) {
			seconds := int64(end.Sub(start).Seconds())
			s.DurationSeconds = &seconds
		}
	}

	events, err := d.QueryEvents(EventFilter{SessionID: sessionID, Limit: 1000000})
	if err != nil {
		return nil, err
	}
	s.EventCount = len(events)
	counts := map[string]int{}
	read, changed := map[string]struct{}{}, map[string]struct{}{}
	for _, e := range events {
		counts[e.ActionType]++
		if e.ActionType == "file_read" && e.FilePath != "" {
			read[e.FilePath] = struct{}{}
		}
		if (e.ActionType == "file_write" || e.ActionType == "file_delete") && e.FilePath != "" {
			changed[e.FilePath] = struct{}{}
		}
		if e.ActionType == "command_exec" && e.HookPhase != "pre" {
			s.Commands = append(s.Commands, CommandActivity{e.Timestamp, e.Command, e.ExitCode, e.ResultStatus})
		}
		if e.ActionType == "mcp_tool_use" && e.HookPhase != "pre" {
			s.MCPTools = append(s.MCPTools, MCPActivity{e.Timestamp, e.MCPServer, firstNonempty(e.MCPTool, e.ToolName), e.ResultStatus})
		}
		if e.IsSensitive && e.HookPhase != "pre" {
			s.SensitiveAccesses = append(s.SensitiveAccesses, e)
		}
		s.Attention = append(s.Attention, findingsForEvent(e)...)
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		s.CountsByAction = append(s.CountsByAction, CountByAction{key, counts[key]})
	}
	s.FilesRead = sortedKeys(read)
	s.FilesChanged = sortedKeys(changed)
	return s, nil
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// NamedCount is a deterministic named aggregate.
type NamedCount struct {
	Name     string `json:"name"`
	Count    int    `json:"count"`
	Sessions int    `json:"sessions,omitempty"`
}

// AccountabilityReport is an aggregate over an explicit local time window.
type AccountabilityReport struct {
	Since                  string               `json:"since"`
	Until                  string               `json:"until"`
	Totals                 ActivityCounts       `json:"totals"`
	Agents                 []NamedCount         `json:"agents"`
	FilesRead              []string             `json:"files_read"`
	FilesChanged           []string             `json:"files_changed"`
	SensitiveAccesses      []StoredEvent        `json:"sensitive_accesses"`
	Attention              []AttentionFinding   `json:"attention"`
	CommandExecutions      int                  `json:"command_executions"`
	CommandFailures        int                  `json:"command_failures"`
	MCPActivity            []NamedCount         `json:"mcp_activity"`
	Developers             []NamedCount         `json:"developers"`
	Branches               []NamedCount         `json:"branches"`
	Repository             string               `json:"repository,omitempty"`
	FileEntries            []ReportPath         `json:"file_entries,omitempty"`
	RepositoryGroups       []RepositoryReport   `json:"repository_groups,omitempty"`
	PathEvidence           []ReportPathEvidence `json:"-"`
	RepositoryFilesRead    []string             `json:"repository_files_read"`
	ExternalFilesRead      []string             `json:"external_files_read"`
	RepositoryFilesChanged []string             `json:"repository_files_changed"`
	ExternalFilesChanged   []string             `json:"external_files_changed"`
}

// ReportPathEvidence retains the captured working directory needed to resolve
// relative stored paths. It is collection metadata, not a JSON compatibility field.
type ReportPathEvidence struct {
	FilePath         string
	WorkingDirectory string
	Kind             string
}

// ReportPath adds display metadata without changing existing JSON path arrays.
type ReportPath struct {
	FilePath         string `json:"file_path"`
	DisplayPath      string `json:"display_path"`
	Repository       string `json:"repository"`
	External         bool   `json:"external"`
	Kind             string `json:"kind"`
	WorkingDirectory string `json:"-"`
	ResolvedPath     string `json:"-"`
}

// RepositoryReport is one repository group in an all-repositories report.
type RepositoryReport struct {
	Repository             string             `json:"repository"`
	Name                   string             `json:"name"`
	Totals                 ActivityCounts     `json:"totals"`
	Agents                 []NamedCount       `json:"agents"`
	FilesRead              []string           `json:"files_read"`
	FilesChanged           []string           `json:"files_changed"`
	FileEntries            []ReportPath       `json:"file_entries"`
	Attention              []AttentionFinding `json:"attention"`
	SensitiveAccesses      []StoredEvent      `json:"sensitive_accesses"`
	CommandExecutions      int                `json:"command_executions"`
	CommandFailures        int                `json:"command_failures"`
	MCPActivity            []NamedCount       `json:"mcp_activity"`
	Developers             []NamedCount       `json:"developers"`
	Branches               []NamedCount       `json:"branches"`
	RepositoryFilesRead    []string           `json:"repository_files_read"`
	ExternalFilesRead      []string           `json:"external_files_read"`
	RepositoryFilesChanged []string           `json:"repository_files_changed"`
	ExternalFilesChanged   []string           `json:"external_files_changed"`
}

// GetAccountabilityReport aggregates already-redacted captured data.
func (d *DB) GetAccountabilityReport(since, until time.Time) (*AccountabilityReport, error) {
	return d.GetAccountabilityReportForSessions(since, until, nil, false)
}

// GetAccountabilityReportForSessions aggregates a selected set of sessions.
func (d *DB) GetAccountabilityReportForSessions(since, until time.Time, sessionIDs []string, restrict bool) (*AccountabilityReport, error) {
	events, err := d.QueryEvents(EventFilter{Since: since, Until: until, Limit: 1000000, SessionIDs: sessionIDs, RestrictSessions: restrict})
	if err != nil {
		return nil, err
	}
	r := &AccountabilityReport{
		Since: since.UTC().Format(time.RFC3339), Until: until.UTC().Format(time.RFC3339),
		Agents: make([]NamedCount, 0), FilesRead: make([]string, 0), FilesChanged: make([]string, 0),
		SensitiveAccesses: make([]StoredEvent, 0), Attention: make([]AttentionFinding, 0),
		MCPActivity: make([]NamedCount, 0), Developers: make([]NamedCount, 0), Branches: make([]NamedCount, 0),
		PathEvidence: make([]ReportPathEvidence, 0),
	}
	sessions, read, changed := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	agents, mcps, developers, branches := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	agentSessions := map[string]map[string]struct{}{}
	pathEvidence := map[string]ReportPathEvidence{}
	for _, e := range events {
		r.Totals.Actions++
		sessions[e.SessionID] = struct{}{}
		agents[e.AgentName]++
		if agentSessions[e.AgentName] == nil {
			agentSessions[e.AgentName] = map[string]struct{}{}
		}
		agentSessions[e.AgentName][e.SessionID] = struct{}{}
		if e.ActionType == "file_read" && e.FilePath != "" {
			read[e.FilePath] = struct{}{}
			key := "read\x00" + e.FilePath + "\x00" + e.WorkingDirectory
			pathEvidence[key] = ReportPathEvidence{FilePath: e.FilePath, WorkingDirectory: e.WorkingDirectory, Kind: "read"}
		}
		if (e.ActionType == "file_write" || e.ActionType == "file_delete") && e.FilePath != "" {
			changed[e.FilePath] = struct{}{}
			key := "changed\x00" + e.FilePath + "\x00" + e.WorkingDirectory
			pathEvidence[key] = ReportPathEvidence{FilePath: e.FilePath, WorkingDirectory: e.WorkingDirectory, Kind: "changed"}
		}
		if e.ActionType == "command_exec" && e.HookPhase != "pre" {
			r.Totals.Commands++
			r.CommandExecutions++
			if (e.ExitCode != nil && *e.ExitCode != 0) || e.ResultStatus == "error" || e.ResultStatus == "failed" || e.ResultStatus == "failure" {
				r.CommandFailures++
			}
		}
		if e.ActionType == "mcp_tool_use" && e.HookPhase != "pre" {
			r.Totals.MCPCalls++
			mcps[firstNonempty(mcpName(e), e.ToolName, "unknown")]++
		}
		if e.IsSensitive && e.HookPhase != "pre" {
			r.Totals.SensitiveAccesses++
			r.SensitiveAccesses = append(r.SensitiveAccesses, e)
		}
		if e.DeveloperEmail != "" {
			developers[e.DeveloperEmail]++
		}
		if e.GitBranch != "" {
			branches[e.GitBranch]++
		}
		r.Attention = append(r.Attention, findingsForEvent(e)...)
	}
	r.Totals.Sessions = len(sessions)
	r.Totals.FilesRead = len(read)
	r.Totals.FilesChanged = len(changed)
	r.FilesRead, r.FilesChanged = sortedKeys(read), sortedKeys(changed)
	r.Agents, r.MCPActivity = namedCounts(agents), namedCounts(mcps)
	for i := range r.Agents {
		r.Agents[i].Sessions = len(agentSessions[r.Agents[i].Name])
	}
	r.Developers, r.Branches = namedCounts(developers), namedCounts(branches)
	evidenceKeys := make([]string, 0, len(pathEvidence))
	for key := range pathEvidence {
		evidenceKeys = append(evidenceKeys, key)
	}
	sort.Strings(evidenceKeys)
	for _, key := range evidenceKeys {
		r.PathEvidence = append(r.PathEvidence, pathEvidence[key])
	}
	return r, nil
}

// SessionRepositoryRef contains repository evidence already stored for a session.
type SessionRepositoryRef struct {
	SessionID        string
	GitRepoURL       string
	WorkingDirectory string
}

// ListSessionRepositories returns deterministic stored repository evidence.
func (d *DB) ListSessionRepositories() ([]SessionRepositoryRef, error) {
	rows, err := d.db.Query(`SELECT id, COALESCE(git_repo_url, ''), COALESCE(working_directory, '') FROM sessions ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list session repositories: %w", err)
	}
	defer rows.Close()
	result := make([]SessionRepositoryRef, 0)
	for rows.Next() {
		var ref SessionRepositoryRef
		if err := rows.Scan(&ref.SessionID, &ref.GitRepoURL, &ref.WorkingDirectory); err != nil {
			return nil, fmt.Errorf("scan session repository: %w", err)
		}
		result = append(result, ref)
	}
	return result, rows.Err()
}

func namedCounts(values map[string]int) []NamedCount {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	result := make([]NamedCount, 0, len(keys))
	for _, key := range keys {
		result = append(result, NamedCount{Name: key, Count: values[key]})
	}
	return result
}
