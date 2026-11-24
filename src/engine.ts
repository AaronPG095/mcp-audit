import { loadAllConfigs } from './discovery/loader.js';
import { getCandidateConfigPaths } from './discovery/paths.js';
import { redactSecret } from './rules/redact.js';
import { STATIC_CONFIG_RULES, STATIC_SERVER_RULES } from './rules/staticRules.js';
import {
  SEVERITY_RANK,
  type AuditResult,
  type DiscoveredConfig,
  type FailOnThreshold,
  type Finding,
  type ScanOptions,
  type Severity,
} from './types.js';

export const TOOL_VERSION = '0.1.0';

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

export function runStaticAudit(options: ScanOptions = {}): AuditResult {
  const cwd = options.cwd ?? process.cwd();
  const candidates = getCandidateConfigPaths(options);
  const configs = loadAllConfigs(candidates);

  const findings: Finding[] = [];
  let serversScanned = 0;
  let configsWithErrors = 0;

  for (const config of configs) {
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

  const sortedFindings = sortFindings(findings);
  const countsBySeverity: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    INFO: 0,
  };
  for (const f of sortedFindings) {
    countsBySeverity[f.severity]++;
  }

  const sanitizedConfigs: DiscoveredConfig[] = configs.map((cfg) => ({
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

  return {
    tool: 'mcp-audit',
    version: TOOL_VERSION,
    scannedAt: new Date().toISOString(),
    cwd,
    configs: sanitizedConfigs,
    findings: sortedFindings,
    summary: {
      configsScanned: sanitizedConfigs.length,
      configsWithErrors,
      serversScanned,
      totalFindings: sortedFindings.length,
      countsBySeverity,
    },
  };
}
