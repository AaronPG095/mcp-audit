import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import { runCli } from '../src/cli.js';
import { runStaticAudit } from '../src/engine.js';

const ROOT = process.cwd();

describe('Red-team and clean fixture suite', () => {
  it('catches all 9 static rules in fixtures/malicious-mcp without exposing raw secrets', () => {
    const maliciousConfigs = [
      path.join(ROOT, 'fixtures', 'malicious-mcp', 'claude_desktop_config.json'),
      path.join(ROOT, 'fixtures', 'malicious-mcp', 'vscode_mcp.json'),
      path.join(ROOT, 'fixtures', 'malicious-mcp', 'codex_config.toml'),
    ];

    const result = runStaticAudit({
      cwd: ROOT,
      includeGlobal: false,
      extraConfigs: maliciousConfigs,
    });

    const ruleIds = new Set(result.findings.map((f) => f.ruleId));
    const expectedRules = [
      'MCP-SEC-001',
      'MCP-SC-001',
      'MCP-SC-002',
      'MCP-SC-003',
      'MCP-NET-001',
      'MCP-PRIV-001',
      'MCP-PRIV-002',
      'MCP-PRIV-003',
      'MCP-PRIV-004',
    ];

    for (const ruleId of expectedRules) {
      assert.ok(ruleIds.has(ruleId), `Expected rule ${ruleId} to fire on malicious fixtures`);
    }

    const serialized = JSON.stringify(result);
    assert.ok(!serialized.includes('ghp_FAKE00000000000000000000000000000001'));
    assert.ok(!serialized.includes('AKIAFAKE000000000001'));
    assert.ok(!serialized.includes('FAKE_BEARER_TOKEN_1234567890'));
  });

  it('produces zero false positives on fixtures/clean-mcp', () => {
    const cleanConfigs = [
      path.join(ROOT, 'fixtures', 'clean-mcp', 'clean_mcp.json'),
      path.join(ROOT, 'fixtures', 'clean-mcp', 'clean_vscode_mcp.json'),
      path.join(ROOT, 'fixtures', 'clean-mcp', 'codex_config.toml'),
    ];

    const result = runStaticAudit({
      cwd: ROOT,
      includeGlobal: false,
      extraConfigs: cleanConfigs,
    });

    assert.equal(result.summary.configsWithErrors, 0);
    assert.equal(result.findings.length, 0, `Expected 0 findings, got: ${JSON.stringify(result.findings)}`);
  });

  it('CLI returns exitCode 1 on malicious, 0 on clean, and 2 on invalid args', () => {
    const mal = runCli([
      'scan',
      '--no-global',
      '--config',
      path.join(ROOT, 'fixtures', 'malicious-mcp', 'claude_desktop_config.json'),
      '--format',
      'json',
    ]);
    assert.equal(mal.exitCode, 1);
    const parsedMal = JSON.parse(mal.stdout) as { summary: { totalFindings: number } };
    assert.ok(parsedMal.summary.totalFindings >= 9);

    const clean = runCli([
      'scan',
      '--no-global',
      '--config',
      path.join(ROOT, 'fixtures', 'clean-mcp', 'clean_mcp.json'),
      '--format',
      'json',
    ]);
    assert.equal(clean.exitCode, 0);
    const parsedClean = JSON.parse(clean.stdout) as { findings: unknown[] };
    assert.equal(parsedClean.findings.length, 0);

    const bad = runCli(['scan', '--format', 'xml']);
    assert.equal(bad.exitCode, 2);
  });
});
