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

## Extension Seams for Milestones 2 & 3
- **Milestone 2 (`--inspect`, `lock`, `diff`):**
  - `McpServerConfig` preserves `transport`, `command`, `args`, `url`, `env`, and `headers` so a read-only MCP client (`initialize`, `tools/list`, `resources/list` only — never `tools/call`) can inspect live tool schemas.
  - Tool-poisoning rules (`MCP-INJ-001..004`) and lockfile drift (`MCP-DRIFT-001`) plug into `src/engine.ts` alongside `STATIC_SERVER_RULES` / `STATIC_CONFIG_RULES` and reuse `Finding` + `AuditResult`.
- **Milestone 3 (`--format sarif`, `THREAT_MODEL.md`):**
  - `src/reporters/sarif.ts` will consume `AuditResult` directly to emit SARIF v2.1.0.
