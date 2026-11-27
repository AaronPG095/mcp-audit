---
title: Plan - Feature: v0.3 Prompts List Inspection And Drift
ticket: local://MCPA:MCPA-Plan-v0-3-Prompts-List-Inspection-And-Drift-2026-11
status: shipped
priority: 
state: 
due: 
appetite: 
version: 
impact: 
blueprint: docs/architecture/MCPA-Blueprint-v0-3-Roadmap.md
devTicketKey: MCPA:MCPA-Plan-v0-3-Prompts-List-Inspection-And-Drift-2026-11
agent: Gemini
branch: feat/v0.3-prompts-list
worktree: MCP-Audit
startedAt: 2026-11-27
reviewedBy: Other
reviewVerdict: pass
reviewSession: research-subagent
baseBranch: main
reviewFingerprint: f08c1286370204a29fa46dd088fba928de4bea6a44e15cc434621d4212d1ba05
pr: https://github.com/AaronPG095/mcp-audit/pull/5
---
# v0.3 Prompts List Inspection And Drift

## Summary

Extend `mcp-audit`'s read-only dynamic inspector, prompt-injection rule engine, and canonical lockfile diff to inspect `prompts/list` metadata (names, descriptions, and argument descriptions) while keeping `prompts/get` and `tools/call` structurally blocked.

## Context

- `src/types.ts`: defines `McpToolSchema`, `McpResourceSchema`, `ServerInspectionResult`, `LockfileServerEntry`.
- `src/inspect/client.ts`: `ALLOWED_READ_ONLY_METHODS` currently allows `initialize`, `notifications/initialized`, `tools/list`, `resources/list`.
- `src/rules/dynamicRules.ts`: `collectSchemaTextFields` collects tool and resource text fields for `MCP-INJ-001..004`.
- `src/lockfile/lockfile.ts`: `buildLockfile` and `diffLockfile` hash and diff tools and resources.

## Open questions

None

## Acceptance criteria

- [x] AC1: `ALLOWED_READ_ONLY_METHODS` includes `prompts/list` while `assertReadOnlyMethod` throws on `prompts/get` and `tools/call`, and both stdio and HTTP inspectors populate `prompts` (falling back to `[]` on `-32601`). verified(cmd): `npm test` exit 0 @5430845
- [x] AC2: `collectSchemaTextFields` includes prompt names, descriptions, and argument descriptions so `MCP-INJ-001..004` detect poisoned prompt metadata. verified(cmd): `npm test` exit 0 @5430845
- [x] AC3: `buildLockfile` and `diffLockfile` hash and diff prompt metadata (`MCP-DRIFT-001`) while remaining backward-compatible with v1 lockfiles that omit `prompts`. verified(cmd): `npm test` exit 0 @5430845
- [x] AC4: `npm run typecheck`, `npm run build`, and `npm test` pass with zero runtime dependencies. verified(cmd): `npm test` exit 0 @5430845

## Steps

- [x] Extend `src/types.ts` and `src/inspect/client.ts` for read-only `prompts/list` inspection (AC1)
- [x] Extend `src/rules/dynamicRules.ts` and `src/lockfile/lockfile.ts` for prompt injection detection and drift diffing (AC2, AC3)
- [x] Update `fixtures/malicious-mcp/mock-poisoned-server.mjs`, `fixtures/clean-mcp/mock-clean-server.mjs`, and `test/inspect.test.ts`, then verify `typecheck`, `build`, and `test` (AC1, AC2, AC3, AC4)

## Risks

- Servers that do not implement MCP prompts return `-32601` (`Method not found`) on `prompts/list`; handled by treating `-32601` as an empty `prompts: []` list just like `resources/list`.
- Existing `mcp-audit.lock.json` files from v0.2.0 lack a `prompts` field; handled by treating `locked.prompts === undefined` as `{}` only when diffing or skipping removed-prompt checks if `locked.prompts` is undefined, while still flagging newly added prompts when `locked.prompts` is present.

## Out of scope

- Calling `prompts/get` (may trigger server-side side effects).
- Markdown reporter (`--format markdown`) and `v0.3.0` release (PR 3).

## Notes

Approved PR 2 plan (from v0.3 roadmap):
> ### PR 2 — Read-Only `prompts/list` Inspection & Prompt Drift
> - **Files:** `src/types.ts`, `src/inspect/client.ts`, `src/rules/dynamicRules.ts`, `src/lockfile/lockfile.ts`, `fixtures/malicious-mcp/mock-poisoned-server.mjs`, `fixtures/clean-mcp/mock-clean-server.mjs`, `test/inspect.test.ts`
> - **Design:**
>   - Add `'prompts/list'` to `ALLOWED_READ_ONLY_METHODS` (still structurally blocking `tools/call`, `prompts/get`, `resources/read`, etc.) across both stdio and Streamable HTTP transports, treating `-32601` (unsupported) gracefully as `[]`.
>   - Feed prompt names, descriptions, and argument descriptions into `collectSchemaTextFields()` so `MCP-INJ-001..004` automatically catch poisoned prompt templates.
>   - Extend `LockfileServerEntry` with optional `prompts` hashes (backward-compatible with existing v1 lockfiles) so `mcp-audit lock` / `diff` catch prompt-template rug-pulls (`MCP-DRIFT-001`).

## Progress log

<!-- One line per session/review, added with `ticket.mjs log` or `ticket.mjs review` -->
- 2026-11-27 11:31 UTC, Other (review: pass): Independent review passed: prompts/list read-only guard, stdio/HTTP support, MCP-INJ scanning, backward-compatible lockfile diff, zero runtime deps, and 33/33 tests pass. [reviewer: research-subagent]
