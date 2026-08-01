# Stage 1 evidence contract 2.0.0

## Status and authority

This directory and `schema/stage1/v2` are the authoritative Stage 1 evidence contract. The SaaS copy is generated and pinned to the SHA-256 of these files. `schema/secuarden-event.schema.json` is the legacy 1.0.0 contract and is not redefined.

The proven capture boundary is Secuarden CLI events produced from Claude Code hooks: session start, pre-tool use, post-tool use, developer intent, and session end. Other agents are not claimed as supported until an adapter has contract fixtures and conformance tests.

## Semantics

`timestamp` is the source event time when supplied, otherwise capture time. `captured_at` is always the CLI observation time. `invocation_id` is the source `tool_use_id` and correlates pre/post lifecycle records. A pre/post event may omit it only when `completeness.state` is `partial` and `completeness.reasons` contains `missing_invocation_id`; it remains conforming partial evidence. Pre/post events always require `tool_name`. Complete evidence has no reasons; partial evidence has at least one.

Outcome dimensions are independent: `outcome` states the observed result, `permission_status` states whether permission was explicitly observed, and `execution_status` states whether it ran. Claude Code requests are `pending/unknown/not_started`; successful posts are `success/unknown/completed`. Receipt of a post event does not prove permission was explicitly allowed. Absence of a post event is not success.

### Outcome vocabulary and producer capability

| Dimension | Canonical/forward-compatible consumer vocabulary | Currently observable from Claude Code hooks |
|---|---|---|
| outcome | pending, success, error, blocked, rejected, cancelled, timed_out, unknown | pending, success, error; otherwise unknown |
| permission_status | unknown, allowed, denied, not_applicable | unknown for tool events; not_applicable for lifecycle events |
| execution_status | not_started, running, completed, failed, cancelled, timed_out, unknown | not_started, completed, failed |

The wider enums accept future producers. This adapter does not claim blocked, rejected, cancelled, timed_out, denied, or allowed unless a future real hook field explicitly supplies that state.

Sequences are unique and contiguous per session. Duplicate event IDs or `(session_id, sequence)` pairs are rejected. Ingestion is idempotent only when an already accepted event ID has byte-equivalent canonical evidence.

## Privacy

- `metadata_only`: implemented and selectable with `"privacy_mode": "metadata_only"` in `~/.secuarden/config.json`; no command, output preview, prompt/intent text, diff, or MCP content is persisted or uploaded. Safe structural fields remain.
- `redacted_content`: bounded command/output/intent fields may be present after deterministic secret redaction.
- `approved_content`: canonical forward-compatible vocabulary, explicitly unsupported by the CLI until an authorization and policy mechanism is proven.

Sensitive paths never carry content fields. Hashes are evidence identifiers, not a claim that content was uploaded.

## Completeness and trust boundaries

Capture, ingestion, and presentation are separate claims. Before persistence the CLI runs producer-invariant validation, not the JSON Schema. It checks contract/version identity, required IDs and positive sequence, parseable timestamps, source identity, the conditional pre/post invocation/tool rule, normalized outcome fields being present, supported producer privacy modes and metadata content omission, lowercase SHA-256 raw hash shape, and non-contradictory completeness state/reasons. It does not generally enforce JSON Schema `additionalProperties`, enums, formats, or patterns. Authoritative JSON Schema validation occurs at the SaaS ingestion boundary. Presentation must use stored completeness and reconciliation counts and must not infer completeness from a summary.

A session is complete only when its expected lifecycle is present, invocation pairs reconcile, sequences are contiguous, integrity verifies, and `captured_event_count == uploaded_event_count == accepted_event_count`. Missing hook halves, capture failures, rejected events, legacy records, or count mismatch make it partial. Summary-only sync is always `summary_only`.

Compliance controls, risk scores, CCR, findings, and policy decisions are derived SaaS data and are outside this evidence contract.

## Compatibility and migration

| Producer | Contract | SaaS handling | Completeness |
|---|---|---|---|
| CLI with v2 conformance | 2.0.0 | validate and ingest | computed, never assumed |
| CLI summary sync | none | retain summary endpoint | `summary_only` |
| Legacy CLI/schema | 1.0.0 | retain/read; do not upgrade in place | `legacy_unverified` |
| Raw Claude endpoint | vendor payload | retain during migration | `legacy_unverified` |
| Other coding agents | none proven | reject from canonical v2 endpoint | unsupported |

Migration is additive: deploy nullable canonical columns and uniqueness constraints, classify existing rows, then enable v2 ingestion. Existing evidence is never discarded or silently promoted. Producers and consumers negotiate by exact `schema_version`; unsupported major versions receive a 422 response.
