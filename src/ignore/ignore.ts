import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type {
  ExpiredSuppressionWarning,
  Finding,
  IgnoreFile,
  SuppressedFinding,
  SuppressionRule,
} from '../types.js';

export const DEFAULT_IGNORE_FILE_NAME = '.mcp-audit-ignore.json';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function normalizePathForMatch(targetPath: string, cwd: string): string {
  const rel = path.relative(cwd, targetPath);
  const candidate = rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel : targetPath;
  const forward = candidate.replaceAll('\\', '/').replace(/^\.\//, '');
  return process.platform === 'win32' ? forward.toLowerCase() : forward;
}

function validateSuppressionRule(entry: unknown, index: number): SuppressionRule {
  if (!isRecord(entry)) {
    throw new Error(`Invalid suppression at index ${index}: expected an object.`);
  }

  const ruleId = typeof entry.ruleId === 'string' ? entry.ruleId.trim() : '';
  if (!ruleId) {
    throw new Error(`Invalid suppression at index ${index}: "ruleId" must be a non-empty string.`);
  }

  const reason = typeof entry.reason === 'string' ? entry.reason.trim() : '';
  if (!reason) {
    throw new Error(
      `Invalid suppression for "${ruleId}" at index ${index}: "reason" is required and must be non-empty.`,
    );
  }

  const serverName =
    typeof entry.serverName === 'string' && entry.serverName.trim()
      ? entry.serverName.trim()
      : undefined;
  const filePath =
    typeof entry.filePath === 'string' && entry.filePath.trim()
      ? entry.filePath.trim()
      : undefined;

  if (!serverName && !filePath) {
    throw new Error(
      `Invalid suppression for "${ruleId}" at index ${index}: must scope at least one of "serverName" or "filePath" (blanket ruleId suppressions are not allowed).`,
    );
  }

  let expiresAt: string | undefined;
  if (entry.expiresAt !== undefined) {
    if (typeof entry.expiresAt !== 'string' || Number.isNaN(Date.parse(entry.expiresAt))) {
      throw new Error(
        `Invalid suppression for "${ruleId}" at index ${index}: "expiresAt" must be a valid ISO-8601 date string.`,
      );
    }
    expiresAt = entry.expiresAt;
  }

  return {
    ruleId,
    serverName,
    filePath,
    reason,
    expiresAt,
  };
}

export function loadIgnoreFile(ignorePath: string, required: boolean): IgnoreFile | null {
  if (!existsSync(ignorePath)) {
    if (required) {
      throw new Error(`Ignore file not found: ${ignorePath}`);
    }
    return null;
  }

  const rawText = readFileSync(ignorePath, 'utf8');
  const cleanText = rawText.charCodeAt(0) === 0xfeff ? rawText.slice(1) : rawText;
  const parsed = JSON.parse(cleanText) as unknown;

  if (!isRecord(parsed) || parsed.version !== 1 || !Array.isArray(parsed.suppressions)) {
    throw new Error(
      `Invalid ignore file format in ${ignorePath}: expected { "version": 1, "suppressions": [...] }.`,
    );
  }

  const suppressions = parsed.suppressions.map((entry, idx) => validateSuppressionRule(entry, idx));
  return {
    version: 1,
    suppressions,
  };
}

function suppressionMatchesFinding(
  rule: SuppressionRule,
  finding: Finding,
  cwd: string,
): boolean {
  if (rule.ruleId !== finding.ruleId) {
    return false;
  }
  if (rule.serverName && rule.serverName !== finding.serverName) {
    return false;
  }
  if (rule.filePath) {
    const expected = rule.filePath.replaceAll('\\', '/').replace(/^\.\//, '');
    const normalizedExpected = process.platform === 'win32' ? expected.toLowerCase() : expected;
    const actualRel = normalizePathForMatch(finding.filePath, cwd);
    const actualFull = finding.filePath.replaceAll('\\', '/');
    const normalizedActualFull = process.platform === 'win32' ? actualFull.toLowerCase() : actualFull;
    if (normalizedExpected !== actualRel && normalizedExpected !== normalizedActualFull) {
      return false;
    }
  }
  return true;
}

export function applySuppressions(
  findings: Finding[],
  ignoreFile: IgnoreFile,
  cwd: string,
  now: Date = new Date(),
): {
  activeFindings: Finding[];
  suppressedFindings: SuppressedFinding[];
  expiredSuppressions: ExpiredSuppressionWarning[];
} {
  const nowMs = now.getTime();
  const activeRules: SuppressionRule[] = [];
  const expiredSuppressions: ExpiredSuppressionWarning[] = [];

  for (const rule of ignoreFile.suppressions) {
    if (rule.expiresAt && Date.parse(rule.expiresAt) < nowMs) {
      expiredSuppressions.push({
        ruleId: rule.ruleId,
        serverName: rule.serverName,
        filePath: rule.filePath,
        reason: rule.reason,
        expiresAt: rule.expiresAt,
      });
    } else {
      activeRules.push(rule);
    }
  }

  const activeFindings: Finding[] = [];
  const suppressedFindings: SuppressedFinding[] = [];

  for (const finding of findings) {
    const matched = activeRules.find((rule) => suppressionMatchesFinding(rule, finding, cwd));
    if (matched) {
      suppressedFindings.push({ finding, suppression: matched });
    } else {
      activeFindings.push(finding);
    }
  }

  return {
    activeFindings,
    suppressedFindings,
    expiredSuppressions,
  };
}
