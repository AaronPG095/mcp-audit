# Threat Model (`mcp-audit`)

`mcp-audit` is a **strictly read-only, zero-dependency** security auditor for Model Context Protocol (MCP) client configurations and server metadata. This document defines the trust boundaries, what `mcp-audit` detects, and what it explicitly **cannot** detect.

---

## 1. Assets & Trust Boundaries

| Asset | Location / Format | Risk if Compromised |
| :--- | :--- | :--- |
| **MCP Client Configs** | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.codex/config.toml`, Claude Desktop/Code, Antigravity/Gemini | Supply-chain compromise, secret leakage, excessive filesystem/shell privileges |
| **Developer Credentials** | `env`, `headers`, `args` in configs; host env vars; `~/.ssh`, `~/.aws`, `~/.gnupg` | Credential theft or lateral movement |
| **LLM Context Window** | Tool names/descriptions/schemas, resource metadata, and prompt templates returned by `tools/list`, `resources/list`, and `prompts/list` | Tool poisoning / prompt injection hijacking model behavior |
| **Schema Integrity** | `mcp-audit.lock.json` canonical SHA-256 snapshots | Silent "rug-pull" mutations to tool, resource, or prompt metadata after initial approval |

### Trust Boundaries
1. **Config Files → `mcp-audit`:** Parsed read-only via built-in JSON, JSONC, and TOML parsers. Configs are never modified.
2. **`mcp-audit` → MCP Servers (`--inspect`, `lock`, `diff`):** Opt-in only. Stdio servers are spawned with a minimal sanitized environment and strict per-server timeout. `assertReadOnlyMethod()` structurally restricts RPC calls to `initialize`, `notifications/initialized`, `tools/list`, `resources/list`, and `prompts/list` — **`tools/call`, `resources/read`, and `prompts/get` are never invoked**.
3. **Output Boundary (Terminal / JSON / SARIF / Markdown):** Secrets matched by `MCP-SEC-001` or secret-named `env`/`headers` keys are redacted via `redactSecret()` before leaving the engine.
4. **Baseline Suppressions (`.mcp-audit-ignore.json`):** Every suppression requires a non-empty `reason` and at least one scope (`serverName` or `filePath`) — blanket `ruleId`-only silencing is rejected. Expired entries (`expiresAt`) stop suppressing and emit warnings.

---

## 2. Threats in Scope & Rule Coverage

| Threat Category | Rules | Detection Mechanism |
| :--- | :--- | :--- |
| **Hardcoded Secrets** | `MCP-SEC-001` (`CRITICAL`) | Known provider prefixes (AWS, GitHub, Anthropic, OpenAI, Google, Slack, Stripe, PEM, Bearer) + high-entropy literal values in secret-named keys |
| **Supply-Chain Drift & RCE** | `MCP-SC-001` (`HIGH`), `MCP-SC-002` (`HIGH`), `MCP-SC-003` (`MEDIUM`) | Unpinned `npx`/`uvx`/`pnpx`/`bunx`, remote/VCS URLs (`git+https://`, `curl \| sh`), shell wrappers (`cmd /c`, `bash -c`, `powershell -c`) |
| **Insecure Transport** | `MCP-NET-001` (`HIGH`) | Non-localhost `http://` endpoints, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `PYTHONHTTPSVERIFY=0`, `--insecure` |
| **Over-Privileged Access** | `MCP-PRIV-001` (`CRITICAL`), `MCP-PRIV-002` (`HIGH`), `MCP-PRIV-003` (`MEDIUM`), `MCP-PRIV-004` (`MEDIUM`→`HIGH`) | Root/home/sensitive host paths, sandbox bypass flags (`--yolo`, `--no-sandbox`), cross-domain env forwarding, toxic read + outbound/exec combinations |
| **Tool Poisoning / Prompt Injection** | `MCP-INJ-001` (`CRITICAL`), `MCP-INJ-002` (`CRITICAL`), `MCP-INJ-003` (`HIGH`), `MCP-INJ-004` (`MEDIUM`) | Instruction overrides (`<IMPORTANT>`, `ignore previous instructions`), credential/file exfiltration directives, cross-tool shadowing, hidden Unicode (zero-width, BiDi, Tag chars `U+E0000`–`U+E007F`) |
| **Schema / Description Rug-Pull** | `MCP-DRIFT-001` (`HIGH`) | Canonical SHA-256 diff of tool descriptions, `inputSchema`, and resources against `mcp-audit.lock.json` |

---

## 3. Explicit Non-Goals & What `mcp-audit` Cannot Catch

Transparently documenting scanner boundaries is critical to avoiding false confidence:

1. **Malicious Runtime Behavior Inside `tools/call` or `prompts/get`:** Because `mcp-audit` never invokes `tools/call` or `prompts/get`, it cannot detect malicious code or dynamic payloads returned only when a tool or prompt is actually executed/rendered.
2. **Delayed / Conditional Rug-Pulls:** A remote or local MCP server that returns clean `tools/list` metadata during `mcp-audit --inspect` and serves poisoned descriptions only to a specific client or after N invocations cannot be caught by a single point-in-time handshake. (`mcp-audit diff` mitigates post-approval drift when run regularly in CI or pre-session.)
3. **Code Execution During Server Startup (`--inspect`):** Opting into `--inspect`, `lock`, or `diff` spawns configured stdio servers (or contacts configured HTTP endpoints) to complete the MCP `initialize` + `tools/list` handshake. **Do not run `--inspect` on untrusted configs** without first reviewing static findings (`mcp-audit scan`).
4. **Obfuscated / Novel Natural-Language Phrasing:** Heuristic regexes in `MCP-INJ-001..003` catch common injection, exfiltration, and shadowing patterns, but cannot guarantee 100% recall against novel semantic social engineering.
5. **OS-Level Process Sandboxing & Network Egress Control:** `mcp-audit` is an auditor, not a runtime sandbox or firewall. Enforcement requires OS containers/sandboxes or client-side permission prompts.
6. **Compromised Host OS or LLM Client Binary:** If the host or MCP client itself is compromised, local config and inspection guarantees do not hold.

---

## 4. Security Guarantees of `mcp-audit` Itself

- **Zero Runtime Dependencies:** `package.json` `dependencies` is `{}` — no third-party transitive packages can introduce supply-chain risk into the auditor itself.
- **Strictly Read-Only:** Never modifies MCP client configs (`lock` only writes `mcp-audit.lock.json` when explicitly invoked).
- **Mandatory Secret Redaction:** Raw secrets are never emitted in terminal, JSON, or SARIF reports.
