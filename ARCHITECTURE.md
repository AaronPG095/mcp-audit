# Architecture (`mcp-audit`)

`mcp-audit` is a zero-dependency, read-only TypeScript/Node.js CLI that audits local and repository MCP configurations for security, supply-chain, and privilege risks.

## Milestone 1 Pipeline (Static Audit)

```
CLI (src/cli.ts)
  └─> Engine (src/engine.ts)
        ├─> Discovery (src/discovery/paths.ts)
        │     Resolves repo-local & OS-specific global client paths (Windows/macOS/Linux)
        ├─> Loader & Parsers (src/discovery/loader.ts, src/parsers/jsonc.ts, src/parsers/toml.ts)
        │     Reads JSON, JSONC, and TOML read-only and normalizes into McpServerConfig[]
        ├─> Static Rule Engine (src/rules/staticRules.ts, src/rules/redact.ts)
        │     Evaluates ServerRule[] and ConfigRule[] (MCP-SEC-001, MCP-SC-001..003,
        │     MCP-NET-001, MCP-PRIV-001..004) with mandatory secret redaction
        └─> Reporters (src/reporters/terminal.ts, src/reporters/json.ts)
              Formats deterministic terminal or JSON output and computes CI exit code
```

## Milestone 2 Pipeline (Dynamic Read-Only Inspection & Schema Drift)

```
CLI (scan --inspect | lock | diff)
  └─> Engine (src/engine.ts: runAudit)
        ├─> Static Pipeline (same as Milestone 1)
        ├─> Read-Only Inspector (src/inspect/client.ts)
        │     Stdio (child_process) & Streamable HTTP/SSE (fetch)
        │     Structurally restricted to: initialize, notifications/initialized, tools/list, resources/list
        ├─> Dynamic Rule Engine (src/rules/dynamicRules.ts)
        │     MCP-INJ-001..004 (prompt injection, exfiltration, shadowing, hidden Unicode)
        │     Dynamic upgrade of MCP-PRIV-004 when live schemas confirm read + outbound/exec
        └─> Schema Lockfile & Drift (src/lockfile/lockfile.ts)
              Canonical SHA-256 hashes in mcp-audit.lock.json; MCP-DRIFT-001 on rug-pull/schema drift
```

## Extension Seams for Milestone 3
- **`--format sarif`, GitHub Action, `THREAT_MODEL.md`:**
  - `src/reporters/sarif.ts` will consume `AuditResult` directly to emit SARIF v2.1.0.
