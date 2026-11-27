import path from 'node:path';
import type { AuditResult } from '../types.js';

function escapeCell(text: string): string {
  return text.replace(/[\r\n]+/g, ' ').replaceAll('|', '\\|').trim();
}

function toDisplayPath(filePath: string, cwd: string): string {
  const rel = path.relative(cwd, filePath);
  if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
    return rel.replaceAll('\\', '/');
  }
  return filePath.replaceAll('\\', '/');
}

/**
 * Formats an AuditResult as GitHub-flavored Markdown suitable for PR comments.
 */
export function formatMarkdownReport(result: AuditResult): string {
  const lines: string[] = [];
  const c = result.summary.countsBySeverity;
  const passed = result.findings.length === 0;

  lines.push(
    passed
      ? `### ✅ mcp-audit v${result.version} — PASS`
      : `### ❌ mcp-audit v${result.version} — ${result.summary.totalFindings} Finding(s) Detected`,
  );
  lines.push('');

  const mode = result.inspections ? 'static + dynamic read-only' : 'static read-only';
  lines.push(
    `Scanned **${result.summary.configsScanned}** config(s), **${result.summary.serversScanned}** enabled server(s) (${mode}).`,
  );
  lines.push('');

  const hasSuppressed = (result.summary.suppressedCount ?? 0) > 0;
  if (hasSuppressed) {
    lines.push('| CRITICAL | HIGH | MEDIUM | INFO | Total | Suppressed |');
    lines.push('| :---: | :---: | :---: | :---: | :---: | :---: |');
    lines.push(
      `| ${c.CRITICAL} | ${c.HIGH} | ${c.MEDIUM} | ${c.INFO} | ${result.summary.totalFindings} | ${result.summary.suppressedCount} |`,
    );
  } else {
    lines.push('| CRITICAL | HIGH | MEDIUM | INFO | Total |');
    lines.push('| :---: | :---: | :---: | :---: | :---: |');
    lines.push(
      `| ${c.CRITICAL} | ${c.HIGH} | ${c.MEDIUM} | ${c.INFO} | ${result.summary.totalFindings} |`,
    );
  }
  lines.push('');

  if (result.expiredSuppressions && result.expiredSuppressions.length > 0) {
    lines.push('> **Warning:** Expired suppressions in `.mcp-audit-ignore.json`:');
    for (const exp of result.expiredSuppressions) {
      const scope = exp.serverName ?? exp.filePath ?? '*';
      lines.push(`> - \`${exp.ruleId}\` (\`${escapeCell(scope)}\`) expired at \`${exp.expiresAt}\``);
    }
    lines.push('');
  }

  if (result.findings.length > 0) {
    lines.push(`<details>`);
    lines.push(`<summary>Findings (${result.findings.length})</summary>`);
    lines.push('');
    lines.push('| Severity | Rule | Server | File | Issue & Remediation |');
    lines.push('| :--- | :--- | :--- | :--- | :--- |');
    for (const f of result.findings) {
      const displayFile = escapeCell(toDisplayPath(f.filePath, result.cwd));
      const detail = f.evidence ? ` Detail: \`${escapeCell(f.evidence)}\`.` : '';
      const issueAndFix = `${escapeCell(f.message)}${detail} **Fix:** ${escapeCell(f.remediation)}`;
      lines.push(
        `| **${f.severity}** | \`${f.ruleId}\` | \`${escapeCell(f.serverName)}\` | \`${displayFile}\` | ${issueAndFix} |`,
      );
    }
    lines.push('');
    lines.push('</details>');
    lines.push('');
  }

  return lines.join('\n');
}
