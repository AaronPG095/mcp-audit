import { createHash } from 'node:crypto';
import path from 'node:path';
import type { AuditResult, Finding, Severity } from '../types.js';

type SarifLevel = 'error' | 'warning' | 'note';

function sarifLevelForSeverity(severity: Severity): SarifLevel {
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
      return 'error';
    case 'MEDIUM':
      return 'warning';
    case 'INFO':
      return 'note';
  }
}

function securitySeverityScore(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return '9.0';
    case 'HIGH':
      return '7.5';
    case 'MEDIUM':
      return '5.0';
    case 'INFO':
      return '2.0';
  }
}

function toArtifactUri(filePath: string, cwd: string): string {
  const rel = path.relative(cwd, filePath);
  if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
    return rel.replaceAll('\\', '/');
  }
  const normalized = filePath.replaceAll('\\', '/');
  if (/^[A-Za-z]:\//.test(normalized)) {
    return `file:///${normalized}`;
  }
  if (normalized.startsWith('/')) {
    return `file://${normalized}`;
  }
  return normalized;
}

function buildResultMessage(finding: Finding): string {
  const parts = [`[${finding.serverName}] ${finding.message}`];
  if (finding.evidence) {
    parts.push(`Detail: ${finding.evidence}`);
  }
  parts.push(`Remediation: ${finding.remediation}`);
  return parts.join(' ');
}

function computeFingerprint(finding: Finding, artifactUri: string): string {
  const input = `${finding.ruleId}|${artifactUri}|${finding.serverName}|${finding.message}`;
  return createHash('sha256').update(input, 'utf8').digest('hex').slice(0, 32);
}

/**
 * Formats an AuditResult as SARIF v2.1.0 JSON for GitHub Code Scanning and CI tools.
 */
export function formatSarifReport(result: AuditResult): string {
  const rulesMap = new Map<
    string,
    {
      id: string;
      name: string;
      shortDescription: { text: string };
      help: { text: string };
      defaultConfiguration: { level: SarifLevel };
      properties: { tags: string[]; 'security-severity': string };
    }
  >();

  const sarifResults = result.findings.map((finding) => {
    if (!rulesMap.has(finding.ruleId)) {
      rulesMap.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleId,
        shortDescription: { text: finding.title },
        help: { text: finding.remediation },
        defaultConfiguration: { level: sarifLevelForSeverity(finding.severity) },
        properties: {
          tags: ['security', 'mcp'],
          'security-severity': securitySeverityScore(finding.severity),
        },
      });
    }

    const artifactUri = toArtifactUri(finding.filePath, result.cwd);

    return {
      ruleId: finding.ruleId,
      level: sarifLevelForSeverity(finding.severity),
      message: { text: buildResultMessage(finding) },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: artifactUri,
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: 1,
            },
          },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: computeFingerprint(finding, artifactUri),
      },
    };
  });

  const sarifLog = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcp-audit',
            version: result.version,
            informationUri: 'https://github.com/AaronPG095/mcp-audit',
            rules: Array.from(rulesMap.values()),
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarifLog, null, 2);
}
