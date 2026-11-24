export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  INFO: 1,
};

export type ClientKind =
  | 'claude-desktop'
  | 'claude-code'
  | 'cursor'
  | 'vscode'
  | 'antigravity'
  | 'gemini'
  | 'codex'
  | 'repo'
  | 'custom';

export type TransportKind = 'stdio' | 'http' | 'sse' | 'unknown';

export type ConfigFormat = 'json' | 'jsonc' | 'toml';

export type ConfigScope = 'repo' | 'global' | 'custom';

export interface CandidateConfigPath {
  path: string;
  client: ClientKind;
  format: ConfigFormat;
  scope: ConfigScope;
  /** Optional nested JSON path hint (e.g., "mcp.servers" for VS Code settings.json). */
  label?: string;
}

export interface McpServerConfig {
  name: string;
  transport: TransportKind;
  command?: string;
  args: string[];
  url?: string;
  env: Record<string, string>;
  headers: Record<string, string>;
  disabled: boolean;
  /** Optional project path if defined under Claude Code's projects[path].mcpServers. */
  projectPath?: string;
  /** Raw normalized entry for future M2 dynamic inspection or custom rules. */
  raw: Record<string, unknown>;
}

export interface DiscoveredConfig {
  path: string;
  client: ClientKind;
  format: ConfigFormat;
  scope: ConfigScope;
  exists: boolean;
  servers: McpServerConfig[];
  parseError?: string;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  message: string;
  remediation: string;
  filePath: string;
  client: ClientKind;
  serverName: string;
  /** Optional redacted snippet or field reference; never contains raw secrets. */
  evidence?: string;
}

export interface AuditSummary {
  configsScanned: number;
  configsWithErrors: number;
  serversScanned: number;
  totalFindings: number;
  countsBySeverity: Record<Severity, number>;
}

export interface AuditResult {
  tool: 'mcp-audit';
  version: string;
  scannedAt: string;
  cwd: string;
  configs: DiscoveredConfig[];
  findings: Finding[];
  summary: AuditSummary;
}

export type OutputFormat = 'terminal' | 'json';

export type FailOnThreshold = Severity | 'none';

export interface ScanOptions {
  cwd?: string;
  extraConfigs?: string[];
  includeGlobal?: boolean;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  homeDir?: string;
}

export interface ServerRule {
  id: string;
  severity: Severity;
  title: string;
  evaluate: (server: McpServerConfig, config: DiscoveredConfig) => Finding[];
}

export interface ConfigRule {
  id: string;
  severity: Severity;
  title: string;
  evaluate: (config: DiscoveredConfig) => Finding[];
}
