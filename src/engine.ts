import { loadAllConfigs } from './discovery/loader.js';
import { getCandidateConfigPaths } from './discovery/paths.js';
import { DEFAULT_INSPECT_TIMEOUT_MS, inspectServer } from './inspect/client.js';
import { diffLockfile, readLockfile } from './lockfile/lockfile.js';
import { DYNAMIC_INSPECTION_RULES, evaluateDynamicToxicCombination } from './rules/dynamicRules.js';
import { redactSecret } from './rules/redact.js';
import { STATIC_CONFIG_RULES, STATIC_SERVER_RULES } from './rules/staticRules.js';
import {
  SEVERITY_RANK,
  type AuditResult,
  type AuditSummary,
  type DiscoveredConfig,
  type FailOnThreshold,
  type Finding,
  type ScanOptions,
  type ServerInspectionResult,
  type Severity,
} from './types.js';

export const TOOL_VERSION = '0.2.0';

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const rankDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (rankDiff !== 0) return rankDiff;
    const pathDiff = a.filePath.localeCompare(b.filePath);
    if (pathDiff !== 0) return pathDiff;
    const serverDiff = a.serverName.localeCompare(b.serverName);
    if (serverDiff !== 0) return serverDiff;
    return a.ruleId.localeCompare(b.ruleId);
  });
}

export function shouldFailAudit(findings: Finding[], failOn: FailOnThreshold): boolean {
  if (failOn === 'none') return false;
  const thresholdRank = SEVERITY_RANK[failOn];
  return findings.some((f) => SEVERITY_RANK[f.severity] >= thresholdRank);
}

function sanitizeConfigs(configs: DiscoveredConfig[]): DiscoveredConfig[] {
  return configs.map((cfg) => ({
    ...cfg,
    servers: cfg.servers.map((srv) => ({
      ...srv,
      env: Object.fromEntries(
        Object.entries(srv.env).map(([k, v]) => [
          k,
          /^\$\{|^%[A-Za-z_]|^\$[A-Za-z_]|^\{\{|^op:\/\/|^env:/.test(v.trim())
            ? v
            : /(?:key|token|secret|password|passwd|pwd|credential|auth)/i.test(k) ||
                /^(?:gh[pousr]_|github_pat_|AKIA|sk-ant-|sk-|AIza|xox[baprs]-|Bearer\s+)/i.test(v)
              ? redactSecret(v)
              : v,
        ]),
      ),
      headers: Object.fromEntries(
        Object.entries(srv.headers).map(([k, v]) => [
          k,
          /^\$\{|^%[A-Za-z_]|^\$[A-Za-z_]|^\{\{/.test(v.trim())
            ? v
            : /(?:authorization|key|token|secret|auth)/i.test(k) || /^Bearer\s+/i.test(v)
              ? redactSecret(v)
              : v,
        ]),
      ),
      raw: {},
    })),
  }));
}

function buildSummary(
  configs: DiscoveredConfig[],
  configsWithErrors: number,
  serversScanned: number,
  findings: Finding[],
): AuditSummary {
  const countsBySeverity: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    INFO: 0,
  };
  for (const f of findings) {
    countsBySeverity[f.severity]++;
  }
  return {
    configsScanned: configs.length,
    configsWithErrors,
    serversScanned,
    totalFindings: findings.length,
    countsBySeverity,
  };
}

function evaluateStaticStage(options: ScanOptions): {
  cwd: string;
  rawConfigs: DiscoveredConfig[];
  findings: Finding[];
  serversScanned: number;
  configsWithErrors: number;
} {
  const cwd = options.cwd ?? process.cwd();
  const candidates = getCandidateConfigPaths(options);
  const rawConfigs = loadAllConfigs(candidates);

  const findings: Finding[] = [];
  let serversScanned = 0;
  let configsWithErrors = 0;

  for (const config of rawConfigs) {
    if (config.parseError) {
      configsWithErrors++;
      continue;
    }

    for (const server of config.servers) {
      if (server.disabled) continue;
      serversScanned++;
      for (const rule of STATIC_SERVER_RULES) {
        findings.push(...rule.evaluate(server, config));
      }
    }

    for (const configRule of STATIC_CONFIG_RULES) {
      findings.push(...configRule.evaluate(config));
    }
  }

  return { cwd, rawConfigs, findings, serversScanned, configsWithErrors };
}

export function runStaticAudit(options: ScanOptions = {}): AuditResult {
  const stage = evaluateStaticStage(options);
  const sortedFindings = sortFindings(stage.findings);
  const sanitizedConfigs = sanitizeConfigs(stage.rawConfigs);

  return {
    tool: 'mcp-audit',
    version: TOOL_VERSION,
    scannedAt: new Date().toISOString(),
    cwd: stage.cwd,
    configs: sanitizedConfigs,
    findings: sortedFindings,
    summary: buildSummary(
      sanitizedConfigs,
      stage.configsWithErrors,
      stage.serversScanned,
      sortedFindings,
    ),
  };
}

export async function runAudit(options: ScanOptions = {}): Promise<AuditResult> {
  const stage = evaluateStaticStage(options);
  let findings = [...stage.findings];
  let inspections: ServerInspectionResult[] | undefined;

  if (options.inspect || options.lockfilePath) {
    const timeoutMs = options.inspectTimeoutMs ?? DEFAULT_INSPECT_TIMEOUT_MS;
    const inspectionTargets: Array<{ config: DiscoveredConfig; serverIdx: number }> = [];

    for (const config of stage.rawConfigs) {
      if (config.parseError) continue;
      config.servers.forEach((srv, idx) => {
        if (!srv.disabled) {
          inspectionTargets.push({ config, serverIdx: idx });
        }
      });
    }

    inspections = await Promise.all(
      inspectionTargets.map(({ config, serverIdx }) =>
        inspectServer(config.servers[serverIdx]!, config.path, timeoutMs),
      ),
    );

    const configByPath = new Map(stage.rawConfigs.map((c) => [c.path, c]));
    for (const insp of inspections) {
      const cfg = configByPath.get(insp.configPath);
      if (!cfg) continue;
      for (const rule of DYNAMIC_INSPECTION_RULES) {
        findings.push(...rule.evaluate(insp, cfg));
      }
    }

    for (const config of stage.rawConfigs) {
      if (config.parseError) continue;
      const upgraded = evaluateDynamicToxicCombination(inspections, config);
      if (upgraded.length > 0) {
        findings = findings.filter(
          (f) => !(f.ruleId === 'MCP-PRIV-004' && f.filePath === config.path),
        );
        findings.push(...upgraded);
      }
    }

    if (options.lockfilePath) {
      const lockfile = readLockfile(options.lockfilePath);
      findings.push(...diffLockfile(lockfile, inspections, stage.rawConfigs, stage.cwd));
    }
  }

  const sortedFindings = sortFindings(findings);
  const sanitizedConfigs = sanitizeConfigs(stage.rawConfigs);

  return {
    tool: 'mcp-audit',
    version: TOOL_VERSION,
    scannedAt: new Date().toISOString(),
    cwd: stage.cwd,
    configs: sanitizedConfigs,
    findings: sortedFindings,
    inspections,
    summary: buildSummary(
      sanitizedConfigs,
      stage.configsWithErrors,
      stage.serversScanned,
      sortedFindings,
    ),
  };
}
