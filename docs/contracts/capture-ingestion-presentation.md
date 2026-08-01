# Evidence pipeline claims

Capture means an adapter observed and locally persisted a hook event. Ingestion means SaaS validated and acknowledged a specific canonical event. Presentation means the UI renders the accepted record and its explicit completeness state. Success at one layer does not prove success at another.

The CLI summary sync transports useful session metadata but no event evidence, so its acknowledgement cannot be displayed as a complete evidence session. Canonical ingestion acknowledgements include accepted and rejected counts; reconciliation is performed against the locally captured count.

If persistence rejects an observed event, the Claude Code hook remains non-blocking. The CLI stores a sanitized capture-failure row (session, phase, category, time only), increments visible capture health, and marks the session partial with `capture_error`. Raw hook payloads, commands, output, prompts, diffs, and raw error details are never copied into that record.
