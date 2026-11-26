---
title: Plan - Feature: Milestone 3 Sarif CI Docs
ticket: local://MCPA:MCPA-Plan-Milestone-3-Sarif-CI-Docs-2026-11
status: in-progress
priority: 
state: 
due: 
appetite: 
version: 
impact: 
devTicketKey: MCPA:MCPA-Plan-Milestone-3-Sarif-CI-Docs-2026-11
agent: Gemini
branch: feat/milestone-3-sarif-ci-docs
worktree: MCP-Audit
startedAt: 2026-11-26
---
# Milestone 3 Sarif CI Docs

## Summary

Implement Milestone 3 of `mcp-audit`: add SARIF v2.1.0 reporting (`--format sarif`), a composite GitHub Action (`action.yml`) and CI workflow (`.github/workflows/ci.yml`), `THREAT_MODEL.md`, `README.md`, MIT `LICENSE`, and `v0.2.0` npm release packaging while preserving zero runtime dependencies and strict read-only guarantees.

## Context

- `src/types.ts`: defines `OutputFormat = 'terminal' | 'json'`.
- `src/cli.ts`: `parseFormat` and `runCli` handle `--format` and exit codes `0`/`1`/`2`.
- `src/engine.ts`: `TOOL_VERSION = '0.2.0'`, `AuditResult` holds `findings`, `configs`, `inspections`, `summary`.
- `package.json`: currently `version: "0.1.0"`, `dependencies: {}` (must remain `{}`).
- `ARCHITECTURE.md`: documents M1 and M2 pipelines and M3 extension seam (`src/reporters/sarif.ts`).

## Open questions

None

## Acceptance criteria

- [x] AC1: `--format sarif` emits valid SARIF v2.1.0 JSON with deduplicated rule descriptors, severity mapping, relative URIs, deterministic `partialFingerprints`, and zero raw secrets. verified(cmd): `npm test` exit 0 @8b2c483
- [x] AC2: `action.yml` (composite GitHub Action) and `.github/workflows/ci.yml` run `mcp-audit` and CI checks cleanly on Linux and Windows. verified: Created action.yml and .github/workflows/ci.yml
- [x] AC3: `THREAT_MODEL.md`, `README.md`, `ARCHITECTURE.md`, and `LICENSE` accurately document all 14 rules, explicit non-goals, and usage. verified: Created THREAT_MODEL.md, README.md, LICENSE, and updated ARCHITECTURE.md
- [x] AC4: `package.json` is bumped to `0.2.0` with zero runtime dependencies and `npm pack --dry-run`, `npm run typecheck`, `npm run build`, and `npm test` all pass. verified(cmd): `npm pack --dry-run` exit 0 @8b2c483

## Steps

- [x] Implement SARIF v2.1.0 reporter (`src/types.ts`, `src/reporters/sarif.ts`, `src/cli.ts`, `test/sarif.test.ts`) (AC1)
- [x] Add composite GitHub Action (`action.yml`) and CI workflow (`.github/workflows/ci.yml`) (AC2)
- [x] Write `THREAT_MODEL.md`, `README.md`, MIT `LICENSE`, and update `ARCHITECTURE.md` (AC3)
- [x] Update `package.json` to `0.2.0` and verify `typecheck`, `build`, `test`, and `npm pack --dry-run` (AC4)

## Risks

- SARIF `artifactLocation.uri` on Windows could contain backslashes or absolute drive paths that fail GitHub Code Scanning ingestion; normalize to forward slashes relative to `cwd`.
- Raw secret leakage in SARIF `message.text` or `partialFingerprints`; `engine.ts` already redacts findings/configs, and `test/sarif.test.ts` explicitly asserts raw synthetic tokens never appear in SARIF output.

## Out of scope

- Runtime sandboxing or intercepting `tools/call` payloads at execution time.
- Publishing to npm registry (`npm publish` is not run; only `npm pack --dry-run` is verified).

## Notes

Approved Milestone 3 plan:
> ### Milestone 3 Plan — SARIF Output, GitHub Action, Threat Model & Release Packaging
> - **Plan / Branch / PR:** `MCPA-Plan-Milestone-3-Sarif-CI-Docs-2026-11.plan.md` on `feat/milestone-3-sarif-ci-docs` → single PR into `main` (with incremental commits).
> 1. **SARIF v2.1.0 Reporter (`src/reporters/sarif.ts`, `src/types.ts`, `src/cli.ts`, `test/sarif.test.ts`)** — Add `'sarif'` to `OutputFormat` and `--format sarif`, emit SARIF v2.1.0 (`runs[0].tool.driver.rules[]`, `results[]`, severity mapping, relative artifact URIs, deterministic `partialFingerprints`), and test schema + redaction + exit codes.
> 2. **GitHub Action & Repo CI (`action.yml`, `.github/workflows/ci.yml`)** — Composite GitHub Action + CI workflow on `ubuntu-latest` and `windows-latest` with Node 22.
> 3. **Threat Model & Portfolio Docs (`THREAT_MODEL.md`, `README.md`, `ARCHITECTURE.md`, `LICENSE`)** — Document trust boundaries, all 14 rules, explicit non-goals/limitations, quickstart, and MIT license.
> 4. **Release Packaging (`package.json`)** — Sync `version` to `0.2.0`, update `files`/`repository`/`homepage`/`bugs`, verify with `npm pack --dry-run`.
> 5. **ADW Lifecycle & Verification** — `adw new` → `adw create --agent Gemini` → branch + commit plan → `adw start` → incremental commits → `adw pack --test` → independent review (`allowSelfReview: false`) → `adw check` → PR #3 → merge.

## Progress log

<!-- One line per session/review, added with `ticket.mjs log` or `ticket.mjs review` -->
