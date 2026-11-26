import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import { runCli } from '../src/cli.js';
import { runStaticAudit } from '../src/engine.js';
import { formatSarifReport } from '../src/reporters/sarif.js';

const ROOT = process.cwd();

interface SarifLog {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          defaultConfiguration: { level: string };
          properties: { tags: string[]; 'security-severity': string };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      level: string;
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string; uriBaseId?: string };
        };
      }>;
      partialFingerprints: { primaryLocationLineHash: string };
    }>;
  }>;
}

describe('SARIF v2.1.0 reporter', () => {
  it('emits valid SARIF v2.1.0 with deduplicated rules, fingerprints, relative URIs, and redacted secrets', () => {
    const result = runStaticAudit({
      cwd: ROOT,
      includeGlobal: false,
      extraConfigs: [path.join(ROOT, 'fixtures', 'malicious-mcp', 'claude_desktop_config.json')],
    });

    const sarifText = formatSarifReport(result);
    const sarif = JSON.parse(sarifText) as SarifLog;

    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
    assert.equal(sarif.runs.length, 1);

    const run = sarif.runs[0]!;
    assert.equal(run.tool.driver.name, 'mcp-audit');
    assert.equal(run.results.length, result.findings.length);

    const ruleIds = run.tool.driver.rules.map((r) => r.id);
    assert.equal(new Set(ruleIds).size, ruleIds.length, 'driver.rules must be deduplicated');

    for (const res of run.results) {
      assert.ok(res.ruleId);
      assert.ok(['error', 'warning', 'note'].includes(res.level));
      assert.ok(res.partialFingerprints.primaryLocationLineHash.length === 32);
      const uri = res.locations[0]?.physicalLocation.artifactLocation.uri ?? '';
      assert.ok(!uri.includes('\\'), `SARIF URI must use forward slashes: ${uri}`);
      assert.equal(uri, 'fixtures/malicious-mcp/claude_desktop_config.json');
    }

    assert.ok(!sarifText.includes('ghp_FAKE00000000000000000000000000000001'));
    assert.ok(!sarifText.includes('FAKE_BEARER_TOKEN_1234567890'));
  });

  it('CLI --format sarif returns exitCode 1 on malicious and 0 on clean', async () => {
    const mal = await runCli([
      'scan',
      '--no-global',
      '--config',
      path.join(ROOT, 'fixtures', 'malicious-mcp', 'claude_desktop_config.json'),
      '--format',
      'sarif',
    ]);
    assert.equal(mal.exitCode, 1);
    const malSarif = JSON.parse(mal.stdout) as SarifLog;
    assert.ok(malSarif.runs[0]!.results.length >= 9);

    const clean = await runCli([
      'scan',
      '--no-global',
      '--config',
      path.join(ROOT, 'fixtures', 'clean-mcp', 'clean_mcp.json'),
      '--format',
      'sarif',
    ]);
    assert.equal(clean.exitCode, 0);
    const cleanSarif = JSON.parse(clean.stdout) as SarifLog;
    assert.equal(cleanSarif.runs[0]!.results.length, 0);
  });
});
