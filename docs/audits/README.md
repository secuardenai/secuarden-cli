# Release scope audits

Method version: **1.0**. These audits separate implemented behavior, observed
validation, product recommendations, and proposed work. They are not security
certifications or release approvals.

## Audit history

| Release | Audit revision | Method | Result |
|---|---|---|---|
| v0.7.0 | 1 | 1.0 | [Recorder baseline and scope cleanup](v0.7.0.md) |

## Dated follow-ups

- [2026-11-17 — recorder workflow cleanup and Codex validation handoff](2026-11-17-v0.7.0-recorder-follow-up.md).
  Baseline revision 1 is unchanged; Codex delivery and repository integrity passed.
  Full live acceptance remains incomplete; see the live-result addendum.

## Classification

- **Keep:** central to capturing, inspecting, and verifying observed activity.
- **Experimental:** implemented, but outside the primary journey; preserve
  compatibility and fix defects while freezing expansion. This is a scope
  recommendation, not a claim that the released command already has this label.
- **Defer:** proposed work not needed to make the recorder dependable. Existing
  pieces do not establish that the complete proposed workflow is implemented.

Classification is independent of validation. Code inspection, automated tests,
synthetic replay, live-agent verification, and deployed-service verification must
be reported separately. Never turn an untested capability into a verified claim.

## Rerun procedure

Run after each major release or substantial scope expansion; any release may be
audited. This checklist is manual, not an installed automation.

1. Record release tag, full commit, date, working-tree state, audit revision,
   method version, and previous audit. Do not include credentials or user data.
2. Inventory registered commands, hooks, storage, upload contracts, documentation,
   and external dependencies. Recheck implementation; do not copy old conclusions.
3. Compare with the previous audit: additions, removals, classification changes,
   resolved findings, regressions, and still-unverified claims.
4. Complete every section in [the template](TEMPLATE.md). Cite source paths and
   symbols, pinned to the audited commit where practical. Mark external systems
   unverified unless actually inspected or exercised.
5. Review the primary journey: install/setup, live delivery, inspection, local
   integrity verification. State exactly which steps were executed. Do not alter
   real hook settings, upload data, or infer live success merely to fill a table.
6. Prioritize a short cleanup list. Separate recommendations from completed fixes;
   retain stable finding IDs and explicit evidence before closing a finding.
7. Save `vX.Y.Z.md` and add it to this index. Preserve previous release audits.
   Corrections to an audit increment its revision and append a correction note;
   do not silently rewrite historical findings. Increment the method version when
   the criteria change and describe the change here.

## Method history

- 1.0 — 2026-11-17: initial classification, evidence, comparison, and correction rules.
