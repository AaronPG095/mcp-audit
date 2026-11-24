import type { AuditResult } from '../types.js';

export function formatJsonReport(result: AuditResult): string {
  return JSON.stringify(result, null, 2);
}
