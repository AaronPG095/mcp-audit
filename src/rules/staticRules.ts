import path from 'node:path';
import type { ConfigRule, DiscoveredConfig, Finding, McpServerConfig, ServerRule } from '../types.js';
import { redactSecret, shannonEntropy } from './redact.js';

function makeFinding(
  rule: { id: string; severity: Finding['severity']; title: string },
  config: DiscoveredConfig,
  serverName: string,
  message: string,
  remediation: string,
  evidence?: string,
): Finding {
  return {
    ruleId: rule.id,
    severity: rule.severity,
    title: rule.title,
    message,
    remediation,
    filePath: config.path,
    client: config.client,
    serverName,
    evidence,
  };
}

function isEnvReference(val: string): boolean {
  const t = val.trim();
  return (
    /^\$\{[A-Za-z0-9_.:-]+\}$/.test(t) ||
    /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(t) ||
    /^%[A-Za-z_][A-Za-z0-9_]*%$/.test(t) ||
    /^\{\{[A-Za-z0-9_.-]+\}\}$/.test(t) ||
    /^op:\/\/.+/.test(t) ||
    /^env:[A-Za-z_][A-Za-z0-9_]*$/.test(t)
  );
}

function isPlaceholder(val: string): boolean {
  const lower = val.trim().toLowerCase();
  if (!lower) return true;
  if (
    lower.includes('your-') ||
    lower.includes('your_') ||
    lower.includes('changeme') ||
    lower.includes('replace-me') ||
    lower.includes('placeholder') ||
    lower === 'example' ||
    lower === 'test' ||
    lower === 'dummy'
  ) {
    return true;
  }
  if (/^(x+|0+|\*+|\.+)$/.test(lower)) return true;
  if (/^<[^>]+>$/.test(lower)) return true;
  return false;
}

const KNOWN_SECRET_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: 'AWS Access Key', regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: 'GitHub Token', regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/ },
  { label: 'GitHub Fine-Grained PAT', regex: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/ },
  { label: 'Anthropic API Key', regex: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/ },
  { label: 'OpenAI API Key', regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/ },
  { label: 'Google API Key', regex: /\bAIza[0-9A-Za-z_-]{30,}\b/ },
  { label: 'Slack Token', regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { label: 'Stripe Key', regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/ },
  { label: 'Private Key Header', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
];

const SECRET_KEY_NAME_REGEX =
  /(?:key|token|secret|password|passwd|pwd|credential|auth|api_key|apikey|private)/i;

// 1. MCP-SEC-001: Hardcoded Secrets in Config
export const ruleHardcodedSecrets: ServerRule = {
  id: 'MCP-SEC-001',
  severity: 'CRITICAL',
  title: 'Hardcoded secret or credential in MCP config',
  evaluate(server, config) {
    const findings: Finding[] = [];

    const checkEntry = (location: string, key: string | undefined, value: string) => {
      if (isEnvReference(value) || isPlaceholder(value)) return;

      for (const pattern of KNOWN_SECRET_PATTERNS) {
        const match = value.match(pattern.regex);
        if (match) {
          findings.push(
            makeFinding(
              this,
              config,
              server.name,
              `${pattern.label} hardcoded in ${location}${key ? ` ("${key}")` : ''}.`,
              'Remove the literal credential from config and reference an environment variable (e.g., "${MY_TOKEN}") or OS keychain.',
              `${location}${key ? `.${key}` : ''} = ${redactSecret(match[0])}`,
            ),
          );
          return;
        }
      }

      if (key && /^authorization$/i.test(key)) {
        const bearerMatch = value.match(/^Bearer\s+(.+)$/i);
        if (bearerMatch && bearerMatch[1] && !isEnvReference(bearerMatch[1]) && !isPlaceholder(bearerMatch[1])) {
          findings.push(
            makeFinding(
              this,
              config,
              server.name,
              `Literal Bearer token hardcoded in ${location} ("${key}").`,
              'Replace the literal Bearer token with an environment variable reference or dynamic auth helper.',
              `${location}.${key} = Bearer ${redactSecret(bearerMatch[1])}`,
            ),
          );
          return;
        }
      }

      if (key && SECRET_KEY_NAME_REGEX.test(key) && value.length >= 16 && shannonEntropy(value) >= 3.2) {
        findings.push(
          makeFinding(
            this,
            config,
            server.name,
            `High-entropy credential hardcoded in ${location} ("${key}").`,
            'Store secrets outside MCP config files and inject them via environment variable references.',
            `${location}.${key} = ${redactSecret(value)}`,
          ),
        );
      }
    };

    for (const [k, v] of Object.entries(server.env)) {
      checkEntry('env', k, v);
    }
    for (const [k, v] of Object.entries(server.headers)) {
      checkEntry('headers', k, v);
    }
    server.args.forEach((arg, idx) => {
      checkEntry(`args[${idx}]`, undefined, arg);
    });

    return findings;
  },
};

function commandBasename(command?: string): string {
  if (!command) return '';
  const normalized = command.replaceAll('\\', '/');
  return path.posix.basename(normalized).toLowerCase().replace(/\.(exe|cmd|bat)$/, '');
}

const EPHEMERAL_RUNNERS = new Set(['npx', 'pnpx', 'bunx', 'uvx']);
const MUTABLE_TAGS = new Set(['latest', 'next', 'canary', 'dev', 'beta', 'alpha', 'nightly', 'edge']);

function isRemoteSpec(spec: string): boolean {
  return /^(?:https?:\/\/|git\+|github:|gitlab:|bitbucket:|ssh:\/\/)/i.test(spec);
}

function extractRunnerPackages(runner: string, args: string[]): string[] {
  const packages: string[] = [];
  let skipNext = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (skipNext) {
      skipNext = false;
      continue;
    }

    if (arg === '--') {
      // Subsequent args are passed to the executed binary, not the package runner.
      break;
    }

    if (arg === '-p' || arg === '--package' || arg === '--from') {
      const next = args[i + 1];
      if (next) {
        packages.push(next);
        skipNext = true;
      }
      continue;
    }

    if (arg.startsWith('--package=') || arg.startsWith('--from=')) {
      const val = arg.split('=', 2)[1];
      if (val) packages.push(val);
      continue;
    }

    if (arg.startsWith('-')) {
      // Runners like npx/uvx have flags like -y, --yes, -q, --quiet
      if (runner === 'uvx' && (arg === '--python' || arg === '--with')) {
        skipNext = true;
      }
      continue;
    }

    // First positional arg is the package spec
    packages.push(arg);
    break;
  }

  return packages;
}

function hasPinnedVersion(pkgSpec: string, runner: string): { pinned: boolean; reason?: string } {
  if (runner === 'uvx') {
    const eqIdx = pkgSpec.indexOf('==');
    if (eqIdx > 0 && eqIdx < pkgSpec.length - 2) {
      return { pinned: true };
    }
    return { pinned: false, reason: 'missing exact "==<version>" pin' };
  }

  // npm / pnpm / bun package spec: [@scope/]name[@version]
  const atIdx = pkgSpec.startsWith('@') ? pkgSpec.indexOf('@', 1) : pkgSpec.indexOf('@');
  if (atIdx === -1 || atIdx === pkgSpec.length - 1) {
    return { pinned: false, reason: 'missing explicit "@<version>" pin' };
  }

  const versionPart = pkgSpec.slice(atIdx + 1).toLowerCase();
  if (MUTABLE_TAGS.has(versionPart)) {
    return { pinned: false, reason: `uses mutable tag "@${versionPart}"` };
  }

  return { pinned: true };
}

// 2. MCP-SC-001: Unpinned Ephemeral Package Runner
export const ruleUnpinnedPackage: ServerRule = {
  id: 'MCP-SC-001',
  severity: 'HIGH',
  title: 'Unpinned ephemeral package runner',
  evaluate(server, config) {
    const runner = commandBasename(server.command);
    if (!EPHEMERAL_RUNNERS.has(runner)) return [];

    const packages = extractRunnerPackages(runner, server.args);
    const findings: Finding[] = [];

    for (const pkg of packages) {
      if (isRemoteSpec(pkg)) continue; // Handled by MCP-SC-002
      const check = hasPinnedVersion(pkg, runner);
      if (!check.pinned) {
        const pinExample = runner === 'uvx' ? `${pkg}==1.2.3` : `${pkg}@1.2.3`;
        findings.push(
          makeFinding(
            this,
            config,
            server.name,
            `Server runs "${runner}" with unpinned package "${pkg}" (${check.reason}).`,
            `Pin the package to an exact, audited version (e.g., "${pinExample}") to prevent silent upstream supply-chain drift.`,
            `${server.command} ${server.args.join(' ')}`.trim(),
          ),
        );
      }
    }

    return findings;
  },
};

// 3. MCP-SC-002: Remote / Non-Registry Code Execution
export const ruleRemoteCodeExecution: ServerRule = {
  id: 'MCP-SC-002',
  severity: 'HIGH',
  title: 'Remote or non-registry package execution',
  evaluate(server, config) {
    const runner = commandBasename(server.command);
    const fullCmd = [server.command ?? '', ...server.args].join(' ');

    if (EPHEMERAL_RUNNERS.has(runner)) {
      const packages = extractRunnerPackages(runner, server.args);
      for (const pkg of packages) {
        if (isRemoteSpec(pkg)) {
          return [
            makeFinding(
              this,
              config,
              server.name,
              `Package runner "${runner}" fetches code from a remote/VCS URL ("${pkg}") instead of a versioned registry.`,
              'Install from a trusted package registry pinned to an exact version or vendor and verify a local commit/tarball hash.',
              fullCmd,
            ),
          ];
        }
      }
    }

    // Pipe-to-shell patterns inside command/args
    if (/(?:curl|wget|irm|invoke-webrequest)\b.*\|\s*(?:sh|bash|zsh|pwsh|powershell|iex)\b/i.test(fullCmd)) {
      return [
        makeFinding(
          this,
          config,
          server.name,
          'Server command downloads and pipes remote code directly into a shell.',
          'Never pipe remote scripts into a shell in MCP configs; install a pinned, verified package instead.',
          fullCmd,
        ),
      ];
    }

    return [];
  },
};

const SHELL_BINARIES = new Set(['cmd', 'powershell', 'pwsh', 'sh', 'bash', 'zsh', 'fish']);
const SHELL_EXEC_FLAGS = new Set(['/c', '/k', '-c', '-command', '-encodedcommand', '-enc']);

// 4. MCP-SC-003: Shell Wrapper Invocation
export const ruleShellWrapper: ServerRule = {
  id: 'MCP-SC-003',
  severity: 'MEDIUM',
  title: 'Server launched via shell wrapper',
  evaluate(server, config) {
    const bin = commandBasename(server.command);
    if (!SHELL_BINARIES.has(bin)) return [];

    const hasExecFlag = server.args.some((a) => SHELL_EXEC_FLAGS.has(a.toLowerCase()));
    if (!hasExecFlag) return [];

    return [
      makeFinding(
        this,
        config,
        server.name,
        `Server "${server.name}" is invoked through shell wrapper "${bin}", obscuring the target binary and expanding command-injection surface.`,
        'Invoke the target executable directly (e.g., "node", "python", or the binary path) instead of wrapping it in a shell.',
        `${server.command} ${server.args.join(' ')}`.trim(),
      ),
    ];
  },
};

function isLocalhostUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    const host = parsed.hostname.toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
  } catch {
    return false;
  }
}

// 5. MCP-NET-001: Insecure Remote Transport / Disabled TLS
export const ruleInsecureTransport: ServerRule = {
  id: 'MCP-NET-001',
  severity: 'HIGH',
  title: 'Insecure remote transport or disabled TLS verification',
  evaluate(server, config) {
    const findings: Finding[] = [];

    if (server.url && /^http:\/\//i.test(server.url) && !isLocalhostUrl(server.url)) {
      findings.push(
        makeFinding(
          this,
          config,
          server.name,
          `Remote MCP URL "${server.url}" uses unencrypted HTTP.`,
          'Use HTTPS ("https://") for all non-localhost MCP endpoints to protect tokens and tool payloads in transit.',
          `url = ${server.url}`,
        ),
      );
    }

    if (server.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' || server.env.PYTHONHTTPSVERIFY === '0') {
      findings.push(
        makeFinding(
          this,
          config,
          server.name,
          'TLS certificate verification is disabled via environment variable.',
          'Remove NODE_TLS_REJECT_UNAUTHORIZED=0 / PYTHONHTTPSVERIFY=0 and configure proper CA trust instead.',
          server.env.NODE_TLS_REJECT_UNAUTHORIZED === '0'
            ? 'NODE_TLS_REJECT_UNAUTHORIZED=0'
            : 'PYTHONHTTPSVERIFY=0',
        ),
      );
    }

    if (server.args.some((a) => a === '--insecure' || a === '-k')) {
      findings.push(
        makeFinding(
          this,
          config,
          server.name,
          'TLS verification bypass flag ("--insecure" / "-k") passed in server args.',
          'Remove the insecure TLS flag and use valid certificates.',
          server.args.join(' '),
        ),
      );
    }

    return findings;
  },
};

function classifySensitivePathArg(arg: string): string | null {
  const trimmed = arg.trim().replace(/^['"]|['"]$/g, '');
  if (!trimmed || trimmed.startsWith('-')) return null;

  // Root paths
  if (trimmed === '/' || trimmed === '\\' || /^[A-Za-z]:[\\/]?$/.test(trimmed)) {
    return `filesystem root "${trimmed}"`;
  }

  // Bare home directory references
  if (
    trimmed === '~' ||
    trimmed === '~/' ||
    trimmed === '~\\' ||
    /^(?:\$HOME|\$\{HOME\}|%USERPROFILE%|%HOME%)$/i.test(trimmed) ||
    /^\/(?:Users|home)\/[^/\\]+\/?$/.test(trimmed) ||
    /^[A-Za-z]:[\\/]Users[\\/][^/\\]+[\\/]?$/i.test(trimmed)
  ) {
    return `entire home directory "${trimmed}"`;
  }

  // Sensitive host directories anywhere in path
  const normalized = trimmed.replaceAll('\\', '/').toLowerCase();
  const sensitiveSegments = ['/.ssh', '/.aws', '/.gnupg', '/.kube', '/.docker', '/etc', '/root', 'c:/windows'];
  for (const seg of sensitiveSegments) {
    if (
      normalized === seg ||
      normalized.startsWith(`${seg}/`) ||
      normalized.includes(`${seg}/`) ||
      normalized.endsWith(seg) ||
      normalized === seg.slice(1) // e.g. ".ssh"
    ) {
      return `sensitive host path "${trimmed}"`;
    }
  }

  return null;
}

// 6. MCP-PRIV-001: Unrestricted Filesystem / Sensitive Host Path Exposure
export const ruleUnrestrictedFilesystem: ServerRule = {
  id: 'MCP-PRIV-001',
  severity: 'CRITICAL',
  title: 'Unrestricted filesystem root or sensitive host path exposed',
  evaluate(server, config) {
    const findings: Finding[] = [];
    for (const arg of server.args) {
      const hit = classifySensitivePathArg(arg);
      if (hit) {
        findings.push(
          makeFinding(
            this,
            config,
            server.name,
            `Server "${server.name}" is granted access to ${hit}.`,
            'Scope filesystem arguments strictly to the specific project directory (e.g., "./src" or a dedicated workspace folder).',
            `arg: ${arg}`,
          ),
        );
      }
    }
    return findings;
  },
};

const BYPASS_FLAGS = new Set([
  '--allow-all',
  '--yolo',
  '--no-sandbox',
  '--disable-sandbox',
  '--dangerously-skip-permissions',
]);

const SHELL_MCP_HINT = /(?:mcp-server-shell|shell-mcp|bash-mcp|terminal-mcp|mcp-shell|command-mcp)/i;

// 7. MCP-PRIV-002: Arbitrary Shell / Unsandboxed Execution
export const ruleUnsandboxedExecution: ServerRule = {
  id: 'MCP-PRIV-002',
  severity: 'HIGH',
  title: 'Arbitrary shell execution or sandbox bypass enabled',
  evaluate(server, config) {
    const bypass = server.args.find((a) => BYPASS_FLAGS.has(a.toLowerCase()));
    if (bypass) {
      return [
        makeFinding(
          this,
          config,
          server.name,
          `Server "${server.name}" uses dangerous permission/sandbox bypass flag "${bypass}".`,
          'Remove the bypass flag and enforce explicit command or path allowlists.',
          `arg: ${bypass}`,
        ),
      ];
    }

    const combined = `${server.name} ${server.command ?? ''} ${server.args.join(' ')}`;
    if (SHELL_MCP_HINT.test(combined)) {
      const hasAllowlist =
        server.args.some((a) => /allow|whitelist|restrict|safe/i.test(a)) ||
        Object.keys(server.env).some((k) => /ALLOW|WHITELIST|RESTRICT/i.test(k));
      if (!hasAllowlist) {
        return [
          makeFinding(
            this,
            config,
            server.name,
            `Server "${server.name}" exposes arbitrary shell/terminal execution without an explicit command allowlist.`,
            'Configure an explicit command allowlist or remove unrestricted shell MCP servers from untrusted workspaces.',
            `${server.command ?? ''} ${server.args.join(' ')}`.trim(),
          ),
        ];
      }
    }

    return [];
  },
};

const SENSITIVE_ENV_VARS: Array<{ envName: string; allowedServerHint: RegExp }> = [
  { envName: 'AWS_SECRET_ACCESS_KEY', allowedServerHint: /aws|s3|bedrock|cloud/i },
  { envName: 'AWS_SESSION_TOKEN', allowedServerHint: /aws|s3|bedrock|cloud/i },
  { envName: 'GITHUB_TOKEN', allowedServerHint: /github|gh\b/i },
  { envName: 'GH_TOKEN', allowedServerHint: /github|gh\b/i },
  { envName: 'GITLAB_TOKEN', allowedServerHint: /gitlab/i },
  { envName: 'OPENAI_API_KEY', allowedServerHint: /openai/i },
  { envName: 'ANTHROPIC_API_KEY', allowedServerHint: /anthropic|claude/i },
  { envName: 'STRIPE_API_KEY', allowedServerHint: /stripe/i },
  { envName: 'DATABASE_URL', allowedServerHint: /postgres|pg|mysql|sqlite|db|database|prisma|supabase/i },
  { envName: 'SLACK_BOT_TOKEN', allowedServerHint: /slack/i },
];

// 8. MCP-PRIV-003: Broad Environment / Credential Forwarding
export const ruleBroadEnvForwarding: ServerRule = {
  id: 'MCP-PRIV-003',
  severity: 'MEDIUM',
  title: 'Broad environment or cross-domain credential forwarding',
  evaluate(server, config) {
    const findings: Finding[] = [];

    const wildcardFlag = server.args.find((a) =>
      /^--(?:allow-env|forward-all-env|inherit-env|pass-env=\*)$/i.test(a),
    );
    if (wildcardFlag) {
      findings.push(
        makeFinding(
          this,
          config,
          server.name,
          `Server "${server.name}" forwards all host environment variables via "${wildcardFlag}".`,
          'Forward only the minimum required environment variables explicitly.',
          `arg: ${wildcardFlag}`,
        ),
      );
    }

    const serverIdentity = `${server.name} ${server.command ?? ''} ${server.args.join(' ')} ${server.url ?? ''}`;
    for (const [envKey, envVal] of Object.entries(server.env)) {
      const upperKey = envKey.toUpperCase();
      const spec = SENSITIVE_ENV_VARS.find((s) => s.envName === upperKey);
      if (!spec) continue;

      // Only flag forwarding here (literal hardcoded secrets are already CRITICAL under MCP-SEC-001)
      if (!isEnvReference(envVal)) continue;

      if (!spec.allowedServerHint.test(serverIdentity)) {
        findings.push(
          makeFinding(
            this,
            config,
            server.name,
            `Sensitive credential "${envKey}" is forwarded to unrelated server "${server.name}".`,
            `Remove "${envKey}" from this server's env block unless it strictly requires that credential.`,
            `env.${envKey} = ${envVal}`,
          ),
        );
      }
    }

    return findings;
  },
};

const SENSITIVE_READ_HINT = /(?:filesystem|fs\b|files|postgres|mysql|sqlite|database|db\b|git\b|email|gmail|obsidian|notes|drive)/i;
const OUTBOUND_OR_EXEC_HINT = /(?:fetch|http|curl|browser|playwright|puppeteer|web|slack|discord|shell|terminal|bash|exec)/i;

// 9. MCP-PRIV-004: Toxic Capability Combination (Config-Level Heuristic)
export const ruleToxicCombination: ConfigRule = {
  id: 'MCP-PRIV-004',
  severity: 'MEDIUM',
  title: 'Toxic capability combination in client config',
  evaluate(config) {
    const enabledServers = config.servers.filter((s) => !s.disabled);
    if (enabledServers.length < 2) return [];

    const readers: string[] = [];
    const exfilCapable: string[] = [];

    for (const server of enabledServers) {
      const fingerprint = `${server.name} ${server.command ?? ''} ${server.args.join(' ')}`;
      if (SENSITIVE_READ_HINT.test(fingerprint)) {
        readers.push(server.name);
      }
      const isRemoteOutbound =
        (server.transport === 'http' || server.transport === 'sse') &&
        !(server.url && isLocalhostUrl(server.url));
      if (OUTBOUND_OR_EXEC_HINT.test(fingerprint) || isRemoteOutbound) {
        exfilCapable.push(server.name);
      }
    }

    const distinctCombination =
      readers.length > 0 &&
      exfilCapable.length > 0 &&
      (readers.length > 1 || exfilCapable.length > 1 || readers[0] !== exfilCapable[0]);

    if (!distinctCombination) return [];

    return [
      makeFinding(
        this,
        config,
        enabledServers.map((s) => s.name).join(', '),
        `Config combines sensitive data access (${readers.join(', ')}) with outbound network/shell capability (${exfilCapable.join(', ')}), creating a potential exfiltration path.`,
        'Isolate high-privilege data servers from outbound network/shell servers in untrusted projects or disable unused servers.',
        `readers=[${readers.join(', ')}], outbound/exec=[${exfilCapable.join(', ')}]`,
      ),
    ];
  },
};

export const STATIC_SERVER_RULES: ServerRule[] = [
  ruleHardcodedSecrets,
  ruleUnpinnedPackage,
  ruleRemoteCodeExecution,
  ruleShellWrapper,
  ruleInsecureTransport,
  ruleUnrestrictedFilesystem,
  ruleUnsandboxedExecution,
  ruleBroadEnvForwarding,
];

export const STATIC_CONFIG_RULES: ConfigRule[] = [ruleToxicCombination];
