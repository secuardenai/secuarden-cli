package storage

const sqlSchema = `
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    agent_name TEXT NOT NULL DEFAULT 'claude-code',
    agent_version TEXT,
    model TEXT,
    developer_name TEXT,
    developer_email TEXT,
    os_user TEXT,
    machine_id TEXT,
    working_directory TEXT,
    git_repo_url TEXT,
    git_branch TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    event_count INTEGER NOT NULL DEFAULT 0,
    capture_failure_count INTEGER NOT NULL DEFAULT 0,
    completeness_state TEXT NOT NULL DEFAULT 'complete',
    completeness_reasons TEXT NOT NULL DEFAULT '[]',
    privacy_mode TEXT NOT NULL DEFAULT 'redacted_content',
    session_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    schema_version TEXT,
    captured_at TEXT,
    invocation_id TEXT,
    source TEXT NOT NULL DEFAULT 'secuarden-cli',
    source_version TEXT,
    agent_name TEXT NOT NULL,
    agent_version TEXT,
    model TEXT,
    provider TEXT,
    hook_phase TEXT NOT NULL,
    action_type TEXT NOT NULL,
    tool_name TEXT,
    result_status TEXT,
    outcome TEXT,
    permission_status TEXT,
    execution_status TEXT,
    privacy_mode TEXT,
    completeness_state TEXT,
    completeness_reasons TEXT,
    is_sensitive INTEGER NOT NULL DEFAULT 0,
    redacted_fields TEXT,
    file_path TEXT,
    affected_files TEXT,
    repository_checkpoint TEXT,
    content_hash TEXT,
    diff_stats TEXT,
    command TEXT,
    exit_code INTEGER,
    command_output_preview TEXT,
    mcp_server TEXT,
    mcp_tool TEXT,
    duration_ms INTEGER,
    working_directory TEXT,
    git_branch TEXT,
    developer_email TEXT,
    intent_summary TEXT,
    raw_event_hash TEXT,
    previous_event_hash TEXT,
    event_hash TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_hash ON events(event_hash) WHERE event_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS session_sync_state (
    session_id TEXT PRIMARY KEY,
    last_synced_event_count INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT,
    last_success_at TEXT,
    last_error TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS capture_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    hook_phase TEXT NOT NULL,
    category TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);
CREATE INDEX IF NOT EXISTS idx_capture_failures_session ON capture_failures(session_id);
`
