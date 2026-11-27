---
title: Blueprint: v0.3 Roadmap
status: active
version: v0.3.0
plannerModel: gemini-4-neon-medium
created: 2026-11-27
---
# Architecture Blueprint: v0.3 Roadmap

## Goal & Non-Goals

- **Goal:** Extend `mcp-audit` for day-to-day team CI adoption across three focused PRs: baseline suppressions with expiry (`.mcp-audit-ignore.json`), read-only `prompts/list` inspection + prompt drift, and a GitHub PR-comment Markdown reporter (`--format markdown`) + `v0.3.0` release.
- **Non-Goals:** No runtime dependencies (`dependencies: {}`), no config mutation, and no `tools/call` or `prompts/get` execution.

## Architecture & Boundaries

- `src/ignore/ignore.ts`: Loads/validates `.mcp-audit-ignore.json` and filters `Finding[]` into `activeFindings`, `suppressedFindings`, and `expiredSuppressions`.
- `src/inspect/client.ts` & `src/rules/dynamicRules.ts` & `src/lockfile/lockfile.ts`: Adds `prompts/list` to `ALLOWED_READ_ONLY_METHODS`, scans prompt metadata via `MCP-INJ-001..004`, and hashes prompt templates in `mcp-audit.lock.json`.
- `src/reporters/markdown.ts` & `action.yml`: Emits GFM Markdown summaries for PR comments.

## Contracts & Invariants

- Zero runtime dependencies (`package.json` `dependencies: {}`).
- Strictly read-only MCP inspection (`initialize`, `notifications/initialized`, `tools/list`, `resources/list`, `prompts/list` only).
- Mandatory secret redaction across active and suppressed findings.

## PR Slice Breakdown

1. **PR 1 — Baseline & Suppression File (`.mcp-audit-ignore.json`):** `src/types.ts`, `src/ignore/ignore.ts`, `src/engine.ts`, `src/cli.ts`, `src/reporters/terminal.ts`, `test/ignore.test.ts`.
2. **PR 2 — Read-Only `prompts/list` Inspection & Prompt Drift:** `src/types.ts`, `src/inspect/client.ts`, `src/rules/dynamicRules.ts`, `src/lockfile/lockfile.ts`, `fixtures/`, `test/inspect.test.ts`.
3. **PR 3 — Markdown Reporter (`--format markdown`), Docs & `v0.3.0` Release:** `src/reporters/markdown.ts`, `src/cli.ts`, `action.yml`, `test/markdown.test.ts`, `README.md`, `THREAT_MODEL.md`, `ARCHITECTURE.md`, `package.json`.

## Living Updates & ADRs

- 2026-11-27: Blueprint created for `v0.3.0`.
