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
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'secuarden-cli',
    source_version TEXT,
    agent_name TEXT NOT NULL,
    hook_phase TEXT NOT NULL,
    action_type TEXT NOT NULL,
    tool_name TEXT,
    result_status TEXT,
    is_sensitive INTEGER NOT NULL DEFAULT 0,
    redacted_fields TEXT,
    file_path TEXT,
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
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action_type);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`
