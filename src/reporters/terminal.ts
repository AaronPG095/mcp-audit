import type { AuditResult, Severity } from '../types.js';

interface Palette {
  reset: string;
  bold: string;
  dim: string;
  red: string;
  yellow: string;
  cyan: string;
  green: string;
  magenta: string;
}

const ANSI_PALETTE: Palette = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  magenta: '\x1b[35m',
};

const PLAIN_PALETTE: Palette = {
  reset: '',
  bold: '',
  dim: '',
  red: '',
  yellow: '',
  cyan: '',
  green: '',
  magenta: '',
};

function colorForSeverity(severity: Severity, p: Palette): string {
  switch (severity) {
    case 'CRITICAL':
      return `${p.bold}${p.red}`;
    case 'HIGH':
      return p.red;
    case 'MEDIUM':
      return p.yellow;
    case 'INFO':
      return p.cyan;
  }
}

export interface TerminalFormatOptions {
  useColor?: boolean;
}

export function formatTerminalReport(
  result: AuditResult,
  options: TerminalFormatOptions = {},
): string {
  const useColor = options.useColor ?? Boolean(process.stdout.isTTY && !process.env.NO_COLOR);
  const p = useColor ? ANSI_PALETTE : PLAIN_PALETTE;
  const lines: string[] = [];

  lines.push(`${p.bold}mcp-audit v${result.version}${p.reset} ${p.dim}(read-only static scan)${p.reset}`);
  lines.push(
    `Scanned ${result.summary.configsScanned} config(s), ${result.summary.serversScanned} enabled server(s).`,
  );

  for (const cfg of result.configs) {
    if (cfg.parseError) {
      lines.push(
        `${p.yellow}[WARN]${p.reset} Could not parse ${cfg.path} (${cfg.client}): ${cfg.parseError}`,
      );
    }
  }

  lines.push('');

  if (result.findings.length === 0) {
    lines.push(`${p.green}${p.bold}PASS${p.reset} No security findings detected.`);
  } else {
    for (const f of result.findings) {
      const sevColor = colorForSeverity(f.severity, p);
      lines.push(
        `${sevColor}[${f.severity}]${p.reset} ${p.bold}${f.ruleId}${p.reset} ${f.title}`,
      );
      lines.push(`  File:   ${f.filePath} (${f.client})`);
      lines.push(`  Server: ${f.serverName}`);
      lines.push(`  Issue:  ${f.message}`);
      if (f.evidence) {
        lines.push(`  Detail: ${p.dim}${f.evidence}${p.reset}`);
      }
      lines.push(`  Fix:    ${f.remediation}`);
      lines.push('');
    }
  }

  const c = result.summary.countsBySeverity;
  lines.push(
    `${p.bold}Summary:${p.reset} CRITICAL=${c.CRITICAL} HIGH=${c.HIGH} MEDIUM=${c.MEDIUM} INFO=${c.INFO} (Total=${result.summary.totalFindings})`,
  );

  return lines.join('\n');
}
