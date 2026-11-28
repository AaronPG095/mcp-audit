# `mcp-audit`

> Fast, **strictly read-only, zero-dependency** security & permission auditor for Model Context Protocol (MCP) configurations and server tool schemas.

`mcp-audit` scans your local machine and project repositories for MCP supply-chain risks, hardcoded secrets, over-privileged filesystem/shell access, hidden prompt-injection payloads in tool descriptions, and schema rug-pulls — with **zero runtime dependencies** and **zero network telemetry**.

---

## Core Principles

- **Strictly Read-Only:** Never modifies user or repository MCP configs. Dynamic inspection (`--inspect`, `lock`, `diff`) is opt-in and structurally restricted via `assertReadOnlyMethod()` to `initialize`, `notifications/initialized`, `tools/list`, `resources/list`, and `prompts/list` — **`tools/call` and `prompts/get` are never invoked**.
- **Zero Runtime Dependencies:** Built solely on Node.js 20+ built-ins (`node:fs`, `node:path`, `node:os`, `node:util`, `node:crypto`, `node:child_process`, `fetch`).
- **Windows-First & Cross-Platform:** Auto-discovers repo-local (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.codex/config.toml`) and global configs on **Windows**, **macOS**, and **Linux** (Claude Desktop, Claude Code, Cursor, VS Code, Antigravity/Gemini, Codex CLI).
- **Secret-Safe Output:** Hardcoded credentials are always redacted (`ghp_...01`) before leaving the rule engine across terminal, JSON, SARIF, and Markdown outputs.

---

## Quickstart

Build the tagged release with Node.js 20 or later:

```bash
git clone --branch v0.3.0 --depth 1 https://github.com/AaronPG095/mcp-audit.git
cd mcp-audit
npm ci
npm run build
node dist/cli.js --version
```

Run the examples from the MCP Audit checkout. Replace `/path/to/project` with the repository you want to audit.

```bash
# Static audit of repo + local client configs
node dist/cli.js scan --cwd /path/to/project

# Repo-only static audit (CI-safe)
node dist/cli.js scan --cwd /path/to/project --no-global

# Static + live read-only tools/list, resources/list & prompts/list inspection
node dist/cli.js scan --cwd /path/to/project --inspect

# Snapshot canonical tool/resource/prompt hashes to mcp-audit.lock.json
node dist/cli.js lock --cwd /path/to/project

# Detect tool, resource, or prompt description/schema drift (rug-pulls) against lockfile
node dist/cli.js diff --cwd /path/to/project

# Emit SARIF v2.1.0 for GitHub Code Scanning
node dist/cli.js scan --cwd /path/to/project --no-global --format sarif > mcp-audit.sarif

# Emit GitHub-flavored Markdown for PR comments
node dist/cli.js scan --cwd /path/to/project --no-global --format markdown

# Apply scoped, expiring baseline suppressions (.mcp-audit-ignore.json)
node dist/cli.js scan --cwd /path/to/project --ignore-file .mcp-audit-ignore.json
```

### Exit Codes
- `0` — Clean (no findings at or above `--fail-on`, default `HIGH`)
- `1` — One or more findings at or above `--fail-on`
- `2` — Invalid CLI usage or runtime error

---

## Rule Catalog (14 Rules)

| Rule ID | Severity | Stage | What It Detects |
| :--- | :--- | :--- | :--- |
| `MCP-SEC-001` | `CRITICAL` | Static | Hardcoded API keys, tokens, PEM keys, Bearer headers, or high-entropy secrets in `env`/`headers`/`args` (always redacted) |
| `MCP-SC-001` | `HIGH` | Static | Unpinned ephemeral package runners (`npx`, `uvx`, `pnpx`, `bunx`) or mutable tags (`@latest`, `@next`) |
| `MCP-SC-002` | `HIGH` | Static | Remote/VCS code execution (`git+https://`, `https://`, `curl \| sh`) |
| `MCP-SC-003` | `MEDIUM` | Static | Shell wrapper invocation (`cmd /c`, `powershell -c`, `bash -c`, `sh -c`) |
| `MCP-NET-001` | `HIGH` | Static | Plaintext `http://` remote MCP URLs (excluding localhost) or disabled TLS verification |
| `MCP-PRIV-001` | `CRITICAL` | Static | Unrestricted filesystem root (`/`, `C:\`), bare home dir (`~`, `%USERPROFILE%`), or sensitive host paths (`.ssh`, `.aws`, `.gnupg`) |
| `MCP-PRIV-002` | `HIGH` | Static | Sandbox/permission bypass flags (`--yolo`, `--no-sandbox`, `--allow-all`) or unrestricted shell MCP servers |
| `MCP-PRIV-003` | `MEDIUM` | Static | Wildcard env forwarding or cross-domain credential forwarding to unrelated servers |
| `MCP-PRIV-004` | `MEDIUM` / `HIGH` | Static → Dynamic | Toxic combination of sensitive read access + outbound network/shell execution (upgraded to `HIGH` when confirmed by `--inspect`) |
| `MCP-INJ-001` | `CRITICAL` | Dynamic | Prompt-injection instruction overrides (`<IMPORTANT>`, `ignore previous instructions`, `do not tell the user`) |
| `MCP-INJ-002` | `CRITICAL` | Dynamic | Credential or sensitive file exfiltration directives (`~/.ssh/id_rsa`, `.aws/credentials`, `.env`, `process.env`) |
| `MCP-INJ-003` | `HIGH` | Dynamic | Cross-tool shadowing or hijacking directives |
| `MCP-INJ-004` | `MEDIUM` | Dynamic | Hidden Unicode obfuscation (zero-width chars, BiDi overrides, Unicode Tag chars `U+E0000`–`U+E007F`, excessive padding) |
| `MCP-DRIFT-001` | `HIGH` | Lock / Diff | Tool/resource/prompt additions, removals, or description/schema hash drift against `mcp-audit.lock.json` |

---

## Sample Terminal Output

```text
mcp-audit v0.2.0 (read-only static scan)
Scanned 1 config(s), 4 enabled server(s).

[CRITICAL] MCP-SEC-001 Hardcoded secret or credential in MCP config
  File:   fixtures/malicious-mcp/claude_desktop_config.json (claude-desktop)
  Server: unpinned-filesystem
  Issue:  GitHub Token hardcoded in env ("GITHUB_TOKEN").
  Detail: env.GITHUB_TOKEN = ghp_...01
  Fix:    Remove the literal credential from config and reference an environment variable (e.g., "${MY_TOKEN}") or OS keychain.

Summary: CRITICAL=3 HIGH=5 MEDIUM=3 INFO=0 (Total=11)
```

---

## GitHub Actions Usage

```yaml
- uses: actions/checkout@v4
- uses: AaronPG095/mcp-audit@v0.3.0
  with:
    fail-on: HIGH
    upload-sarif: 'true'
```

---

## Documentation & Red-Team Fixtures

- [THREAT_MODEL.md](THREAT_MODEL.md) — Trust boundaries, rule coverage, and explicit limitations (what `mcp-audit` cannot catch).
- [ARCHITECTURE.md](ARCHITECTURE.md) — Static, dynamic inspection, lockfile, and SARIF pipeline architecture.
- [fixtures/malicious-mcp/](fixtures/malicious-mcp/) & [fixtures/clean-mcp/](fixtures/clean-mcp/) — Red-team test suite (including mock poisoned/clean stdio MCP servers).
- [AGENTS.md](AGENTS.md) — Non-negotiable invariants and development workflow.
