---
title: Plan - Feature: v0.3 Baseline Suppression File
ticket: local://MCPA:MCPA-Plan-v0-3-Baseline-Suppression-File-2026-11
status: in-progress
priority: 
state: 
due: 
appetite: 
version: 
impact: 
blueprint: docs/architecture/MCPA-Blueprint-v0-3-Roadmap.md
devTicketKey: MCPA:MCPA-Plan-v0-3-Baseline-Suppression-File-2026-11
agent: Gemini
branch: feat/v0.3-ignore-baseline
worktree: MCP-Audit
startedAt: 2026-11-27
reviewedBy: Other
reviewVerdict: pass
reviewSession: research-subagent
baseBranch: main
reviewFingerprint: 8cc517dd29bc89b10582b407f2796c6671c5325236a2c33cfaf1efb51206044e
---
# v0.3 Baseline Suppression File

## Summary

Add support for a baseline suppression file (`.mcp-audit-ignore.json` by default, or `--ignore-file <path>`, bypassed via `--no-ignore`) so teams can record scoped, justified, optionally expiring exceptions without silencing active findings.

## Context

- `src/types.ts`: holds `Finding`, `ScanOptions`, `AuditSummary`, `AuditResult`.
- `src/engine.ts`: `runStaticAudit` and `runAudit` sort findings, compute `countsBySeverity`, and return `AuditResult`.
- `src/cli.ts`: `runCli` parses CLI flags and checks `shouldFailAudit(result.findings, failOn)`.
- `src/reporters/terminal.ts`: formats `AuditResult` and summary counts.

## Open questions

None

## Acceptance criteria

- [x] AC1: `loadIgnoreFile` validates `version === 1`, non-empty `ruleId` and `reason`, at least one scope (`serverName` or `filePath`), and valid `expiresAt` ISO dates, throwing on invalid entries or missing explicit `--ignore-file`. verified(cmd): `npm test` exit 0 @079c031
- [x] AC2: `applySuppressions` moves matching non-expired findings into `suppressedFindings`, leaves expired entries active while recording `expiredSuppressions`, and drops CLI exit code from `1` to `0` when all findings `>= --fail-on` are suppressed. verified(cmd): `npm test` exit 0 @079c031
- [x] AC3: `--no-ignore` bypasses `.mcp-audit-ignore.json` so all findings remain active and `--fail-on` exits `1`. verified(cmd): `npm test` exit 0 @079c031
- [x] AC4: `npm run typecheck`, `npm run build`, and `npm test` pass with zero runtime dependencies. verified(cmd): `npm test` exit 0 @079c031

## Steps

- [x] Implement `SuppressionRule` types, `loadIgnoreFile`, and `applySuppressions` (`src/types.ts`, `src/ignore/ignore.ts`) (AC1, AC2)
- [x] Integrate ignore loading, `--ignore-file`, `--no-ignore`, and warnings into `src/engine.ts`, `src/cli.ts`, and `src/reporters/terminal.ts` (AC2, AC3)
- [x] Add `test/ignore.test.ts` covering scoping, expiry, validation, `--no-ignore`, and missing `--ignore-file`, then verify `typecheck`, `build`, and `test` (AC1, AC2, AC3, AC4)

## Risks

- Blanket `ruleId`-only suppressions could accidentally silence an entire security category repo-wide; mitigated by requiring at least one of `serverName` or `filePath`.
- Windows backslash vs POSIX forward-slash path differences in `filePath` matching; mitigated by normalizing relative paths to forward slashes and comparing case-insensitively on `win32`.

## Out of scope

- `prompts/list` inspection (PR 2) and `--format markdown` reporter (PR 3).

## Notes

Approved PR 1 plan:
> ### PR 1 — Baseline & Suppression File (`.mcp-audit-ignore.json`)
> - **Files:** `src/types.ts`, `src/ignore/ignore.ts`, `src/engine.ts`, `src/cli.ts`, `src/reporters/terminal.ts`, `test/ignore.test.ts`
> - **Design:**
>   - Auto-loads `<cwd>/.mcp-audit-ignore.json` (override with `--ignore-file <path>`, disable with `--no-ignore`).
>   - Schema: `{ version: 1, suppressions: [{ ruleId, serverName?, filePath?, reason, expiresAt? }] }`.
>   - **Guardrails:** Every suppression requires a non-empty `reason` **and** at least one scope (`serverName` or `filePath` — no blanket repo-wide rule silencing). Expired entries (`expiresAt < now`) stop suppressing and surface a warning so stale exceptions don't linger.
>   - Active `findings` drive `--fail-on` exit codes; suppressed items are tracked separately in `AuditResult.suppressedFindings` and shown in the summary count.

## Progress log

<!-- One line per session/review, added with `ticket.mjs log` or `ticket.mjs review` -->
- 2026-11-27 00:22 UTC, Other (review: pass): Independent review passed: scoped .mcp-audit-ignore.json validation, expiry handling, --no-ignore, zero runtime deps, and 30/30 tests pass. [reviewer: research-subagent]
