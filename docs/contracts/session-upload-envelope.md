# SaaS session upload envelope 1.0

`schema/upload/v1/session-envelope.schema.json` is the shared CLI/SaaS contract. The CLI posts it to the existing authenticated HTTPS `session-sync` endpoint. The old summary properties remain at the envelope top level for a practical migration path; SaaS processing is outside this change.

The envelope is assembled only from the local SQLite session and event rows, after existing sensitive-path handling and deterministic redaction. Events are ordered by their per-session `sequence`. `raw_event_hash`, `previous_event_hash`, `event_hash`, and `session_hash` expose the existing integrity evidence. `idempotency_key` is a deterministic SHA-256 over the contract version, session identity/hash, event count, and ordered events, and is also sent as the HTTP `Idempotency-Key` header. Retrying an unchanged envelope therefore has the same key; a newly captured event produces a new key.

## Availability limits

- Intent is present only when the agent emits a supported prompt/intent hook. Claude Code tool hooks often provide no intent, so `intent_summary` is omitted. In `metadata_only` mode intent text is never persisted or uploaded.
- Model and agent version are present only when the hook payload supplies them. They are omitted rather than inferred.
- MCP arguments and responses are deliberately unavailable. Only the already-captured server, tool, outcome, timing, and correlation metadata can be uploaded.
- File contents and raw diffs are not captured by this contract. Sensitive paths never carry content fields. Command/output fields are absent in `metadata_only` mode and redacted before storage in `redacted_content` mode.
- Legacy SQLite events can lack newer evidence fields; their session completeness describes that limitation.

The synthetic `fixtures/upload/v1/session-envelope.json` can be submitted directly for SaaS contract testing without running Claude Code.
