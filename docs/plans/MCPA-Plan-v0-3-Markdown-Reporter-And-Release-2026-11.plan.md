---
title: Plan - Feature: v0.3 Markdown Reporter And Release
ticket: local://MCPA:MCPA-Plan-v0-3-Markdown-Reporter-And-Release-2026-11
status: in-progress
priority: 
state: 
due: 
appetite: 
version: 
impact: 
blueprint: docs/architecture/MCPA-Blueprint-v0-3-Roadmap.md
devTicketKey: MCPA:MCPA-Plan-v0-3-Markdown-Reporter-And-Release-2026-11
agent: Gemini
branch: feat/v0.3-markdown-release
worktree: MCP-Audit
startedAt: 2026-11-27
---
# v0.3 Markdown Reporter And Release

## Summary

Add a GitHub-flavored Markdown reporter (`--format markdown`) and `action.yml` `markdown-file` output for PR comments, sync `README.md`, `THREAT_MODEL.md`, and `ARCHITECTURE.md` with all v0.3 capabilities, and bump `package.json` + `TOOL_VERSION` to `0.3.0`.

## Context

- `src/types.ts`: `OutputFormat = 'terminal' | 'json' | 'sarif'`.
- `src/cli.ts`: `parseFormat` and `runCli` handle `--format`.
- `src/engine.ts`: `TOOL_VERSION = '0.2.0'`.
- `action.yml`: supports `format: terminal | json | sarif` and `sarif-file`.
- `package.json`: `version: "0.2.0"`.

## Open questions

None

## Acceptance criteria

- [ ] AC1: `--format markdown` emits a GFM Markdown report with PASS/FAIL header, severity summary table, suppressed count, collapsible `<details>` findings table with redacted evidence, and zero raw secrets.
- [ ] AC2: `action.yml` supports `format: markdown` and `markdown-file` output path.
- [ ] AC3: `README.md`, `THREAT_MODEL.md`, and `ARCHITECTURE.md` accurately document `.mcp-audit-ignore.json`, `prompts/list` (and `prompts/get` non-goal), and `--format markdown`.
- [ ] AC4: `package.json` and `TOOL_VERSION` are bumped to `0.3.0`, `npm run typecheck`, `npm run build`, `npm test`, and `npm pack --dry-run` pass with zero runtime dependencies.

## Steps

- [x] Implement `src/reporters/markdown.ts`, wire `--format markdown` in `src/types.ts` and `src/cli.ts`, update `action.yml`, and add `test/markdown.test.ts` (AC1, AC2)
- [ ] Update `README.md`, `THREAT_MODEL.md`, `ARCHITECTURE.md`, `src/engine.ts`, and `package.json` to `0.3.0`, then verify `typecheck`, `build`, `test`, and `npm pack --dry-run` (AC3, AC4)

## Risks

- Pipe characters (`|`), backticks, or newlines inside finding messages/evidence could break Markdown table cells; mitigated by escaping `|` as `\|` and collapsing newlines to spaces inside table cells.

## Out of scope

- Running `npm publish` (only `npm pack --dry-run` is verified).

## Notes

Approved PR 3 plan (from v0.3 roadmap):
> ### PR 3 — Markdown Reporter (`--format markdown`), Docs & `v0.3.0` Release
> - **Files:** `src/reporters/markdown.ts`, `src/types.ts`, `src/cli.ts`, `action.yml`, `test/markdown.test.ts`, `README.md`, `THREAT_MODEL.md`, `ARCHITECTURE.md`, `package.json`, `src/engine.ts`
> - **Design:**
>   - Add `--format markdown` emitting a GitHub-flavored Markdown report (PASS/FAIL header, severity summary table, suppressed count, collapsible `<details>` findings table with redacted evidence & remediation) ideal for GitHub PR comments.
>   - Update `action.yml` to support `format: markdown` and optional `markdown-file` output.
>   - Sync docs (`README.md`, `THREAT_MODEL.md`, `ARCHITECTURE.md`), bump to `0.3.0`, verify `npm pack --dry-run`, and cut `v0.3.0`.

## Progress log

<!-- One line per session/review, added with `ticket.mjs log` or `ticket.mjs review` -->
