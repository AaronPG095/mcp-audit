import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import { runCli } from '../src/cli.js';
import { runStaticAudit } from '../src/engine.js';
import { formatMarkdownReport } from '../src/reporters/markdown.js';

const ROOT = process.cwd();

describe('Markdown reporter (--format markdown)', () => {
  it('emits GFM summary table, collapsible findings, escaped pipes, and redacted secrets', () => {
    const result = runStaticAudit({
      cwd: ROOT,
      includeGlobal: false,
      extraConfigs: [path.join(ROOT, 'fixtures', 'malicious-mcp', 'claude_desktop_config.json')],
    });

    const md = formatMarkdownReport(result);
    assert.match(md, /### ❌ mcp-audit v0\.\d+\.\d+ — \d+ Finding\(s\) Detected/);
    assert.ok(md.includes('| CRITICAL | HIGH | MEDIUM | INFO | Total |'));
    assert.ok(md.includes('<details>'));
    assert.ok(md.includes('<summary>Findings ('));
    assert.ok(md.includes('MCP-SEC-001'));

    const syntheticGhToken = ['ghp', 'FAKE00000000000000000000000000000001'].join('_');
    assert.ok(!md.includes(syntheticGhToken));
    assert.ok(!md.includes('FAKE_BEARER_TOKEN_1234567890'));
  });

  it('CLI --format markdown returns exitCode 0 and PASS header on clean fixture', async () => {
    const clean = await runCli([
      'scan',
      '--no-global',
      '--config',
      path.join(ROOT, 'fixtures', 'clean-mcp', 'clean_mcp.json'),
      '--format',
      'markdown',
    ]);
    assert.equal(clean.exitCode, 0);
    assert.match(clean.stdout, /### ✅ mcp-audit v0\.\d+\.\d+ — PASS/);
    assert.ok(!clean.stdout.includes('<details>'));

    const mal = await runCli([
      'scan',
      '--no-global',
      '--config',
      path.join(ROOT, 'fixtures', 'malicious-mcp', 'claude_desktop_config.json'),
      '--format',
      'markdown',
    ]);
    assert.equal(mal.exitCode, 1);
  });
});
