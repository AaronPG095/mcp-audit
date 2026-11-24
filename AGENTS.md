# AGENTS.md — `mcp-audit`

## Non-Negotiable Invariants
- **Strictly read-only:** Never modify user or repository MCP configuration files. Never invoke MCP tools (`tools/call`).
- **Zero runtime dependencies:** `package.json` `dependencies` must remain empty (`{}`). Use Node.js 20+ built-ins (`node:fs`, `node:path`, `node:os`, `node:util`, `node:test`, `node:crypto`).
- **Never leak raw secrets:** Any secret detected by `MCP-SEC-001` must be redacted via `redactSecret()` before leaving the rule engine.

## Commands
- Typecheck: `npm run typecheck`
- Build: `npm run build`
- Test: `npm test`

## Git & PR Workflow
- Create a feature branch per milestone or feature (`feat/...`, `fix/...`).
- Run `npm run typecheck`, `npm run build`, and `npm test` before committing.
- Push the branch and open a PR into `main`.
