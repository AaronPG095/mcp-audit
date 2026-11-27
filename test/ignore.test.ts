import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { runCli } from '../src/cli.js';
import { runStaticAudit } from '../src/engine.js';
import { applySuppressions, loadIgnoreFile } from '../src/ignore/ignore.js';
import type { Finding } from '../src/types.js';

describe('Baseline suppression file (.mcp-audit-ignore.json)', () => {
  it('suppresses matching findings by ruleId + serverName and drops CLI exitCode from 1 to 0', async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'mcp-audit-ignore-'));
    try {
      writeFileSync(
        path.join(tmpDir, '.mcp.json'),
        JSON.stringify({
          mcpServers: {
            legacy: {
              command: 'npx',
              args: ['-y', '@acme/legacy-mcp'],
            },
          },
        }),
        'utf8',
      );

      const before = await runCli(['scan', '--cwd', tmpDir, '--no-global', '--format', 'json']);
      assert.equal(before.exitCode, 1);

      writeFileSync(
        path.join(tmpDir, '.mcp-audit-ignore.json'),
        JSON.stringify({
          version: 1,
          suppressions: [
            {
              ruleId: 'MCP-SC-001',
              serverName: 'legacy',
              reason: 'Internal package has no versioned tags yet; pinned in lockfile.',
            },
          ],
        }),
        'utf8',
      );

      const after = await runCli(['scan', '--cwd', tmpDir, '--no-global', '--format', 'json']);
      assert.equal(after.exitCode, 0);
      const parsed = JSON.parse(after.stdout) as {
        findings: unknown[];
        suppressedFindings: Array<{ finding: { ruleId: string } }>;
        summary: { totalFindings: number; suppressedCount: number };
      };
      assert.equal(parsed.findings.length, 0);
      assert.equal(parsed.suppressedFindings.length, 1);
      assert.equal(parsed.suppressedFindings[0]!.finding.ruleId, 'MCP-SC-001');
      assert.equal(parsed.summary.totalFindings, 0);
      assert.equal(parsed.summary.suppressedCount, 1);

      // --no-ignore bypasses .mcp-audit-ignore.json
      const bypassed = await runCli([
        'scan',
        '--cwd',
        tmpDir,
        '--no-global',
        '--no-ignore',
        '--format',
        'json',
      ]);
      assert.equal(bypassed.exitCode, 1);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('matches relative filePath cross-platform', () => {
    const findings: Finding[] = [
      {
        ruleId: 'MCP-SC-001',
        severity: 'HIGH',
        title: 'Unpinned package',
        message: 'Unpinned',
        remediation: 'Pin it',
        filePath: path.join('/workspace', '.cursor', 'mcp.json'),
        client: 'cursor',
        serverName: 'docs',
      },
    ];

    const applied = applySuppressions(
      findings,
      {
        version: 1,
        suppressions: [
          {
            ruleId: 'MCP-SC-001',
            filePath: '.cursor/mcp.json',
            reason: 'Scoped to cursor workspace config.',
          },
        ],
      },
      '/workspace',
    );

    assert.equal(applied.activeFindings.length, 0);
    assert.equal(applied.suppressedFindings.length, 1);
  });

  it('does not suppress expired entries and records expiredSuppressions warning', () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'mcp-audit-expired-'));
    try {
      writeFileSync(
        path.join(tmpDir, '.mcp.json'),
        JSON.stringify({
          mcpServers: {
            legacy: { command: 'npx', args: ['-y', '@acme/legacy-mcp'] },
          },
        }),
        'utf8',
      );
      writeFileSync(
        path.join(tmpDir, '.mcp-audit-ignore.json'),
        JSON.stringify({
          version: 1,
          suppressions: [
            {
              ruleId: 'MCP-SC-001',
              serverName: 'legacy',
              reason: 'Temporary waiver',
              expiresAt: '2020-01-01T00:00:00Z',
            },
          ],
        }),
        'utf8',
      );

      const res = runStaticAudit({ cwd: tmpDir, includeGlobal: false });
      assert.equal(res.findings.length, 1);
      assert.equal(res.expiredSuppressions?.length, 1);
      assert.equal(res.summary.expiredSuppressionsCount, 1);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('rejects missing reason, unscoped blanket suppression, and missing explicit --ignore-file', async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'mcp-audit-invalid-ignore-'));
    try {
      const noReasonPath = path.join(tmpDir, 'no-reason.json');
      writeFileSync(
        noReasonPath,
        JSON.stringify({
          version: 1,
          suppressions: [{ ruleId: 'MCP-SC-001', serverName: 'foo', reason: '   ' }],
        }),
        'utf8',
      );
      assert.throws(() => loadIgnoreFile(noReasonPath, true), /reason/);

      const unscopedPath = path.join(tmpDir, 'unscoped.json');
      writeFileSync(
        unscopedPath,
        JSON.stringify({
          version: 1,
          suppressions: [{ ruleId: 'MCP-SC-001', reason: 'Blanket ignore' }],
        }),
        'utf8',
      );
      assert.throws(() => loadIgnoreFile(unscopedPath, true), /serverName.*filePath/);

      const missingRes = await runCli([
        'scan',
        '--cwd',
        tmpDir,
        '--no-global',
        '--ignore-file',
        path.join(tmpDir, 'does-not-exist.json'),
      ]);
      assert.equal(missingRes.exitCode, 2);
      assert.match(missingRes.stderr, /Ignore file not found/);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
