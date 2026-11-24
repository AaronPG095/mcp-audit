import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { extractServersFromParsedConfig } from '../src/discovery/loader.js';
import { getCandidateConfigPaths } from '../src/discovery/paths.js';

describe('Config path discovery', () => {
  it('discovers Windows global and repo paths without duplicates', () => {
    const paths = getCandidateConfigPaths({
      platform: 'win32',
      cwd: 'C:\\repo',
      homeDir: 'C:\\Users\\dev',
      env: { APPDATA: 'C:\\Users\\dev\\AppData\\Roaming' },
      includeGlobal: true,
    });

    const rawPaths = paths.map((p) => p.path);
    assert.ok(rawPaths.includes('C:\\repo\\.mcp.json'));
    assert.ok(rawPaths.includes('C:\\repo\\.cursor\\mcp.json'));
    assert.ok(rawPaths.includes('C:\\repo\\.vscode\\mcp.json'));
    assert.ok(rawPaths.includes('C:\\repo\\.codex\\config.toml'));
    assert.ok(rawPaths.includes('C:\\Users\\dev\\AppData\\Roaming\\Claude\\claude_desktop_config.json'));
    assert.ok(rawPaths.includes('C:\\Users\\dev\\.gemini\\antigravity\\mcp_config.json'));
    assert.ok(rawPaths.includes('C:\\Users\\dev\\.codex\\config.toml'));
  });

  it('discovers macOS and Linux global paths', () => {
    const mac = getCandidateConfigPaths({
      platform: 'darwin',
      cwd: '/work/app',
      homeDir: '/Users/dev',
      env: {},
      includeGlobal: true,
    }).map((p) => p.path);
    assert.ok(mac.includes('/Users/dev/Library/Application Support/Claude/claude_desktop_config.json'));
    assert.ok(mac.includes('/Users/dev/.codex/config.toml'));

    const linux = getCandidateConfigPaths({
      platform: 'linux',
      cwd: '/work/app',
      homeDir: '/home/dev',
      env: {},
      includeGlobal: true,
    }).map((p) => p.path);
    assert.ok(linux.includes('/home/dev/.config/Claude/claude_desktop_config.json'));
    assert.ok(linux.includes('/home/dev/.claude.json'));
  });

  it('skips global paths when includeGlobal is false', () => {
    const paths = getCandidateConfigPaths({
      platform: 'win32',
      cwd: 'C:\\repo',
      homeDir: 'C:\\Users\\dev',
      includeGlobal: false,
    });
    assert.equal(paths.length, 4);
    assert.ok(paths.every((p) => p.scope === 'repo'));
  });
});

describe('Config server extraction', () => {
  it('extracts servers from mcpServers, servers, mcp.servers, mcp_servers, and projects', () => {
    const parsed = {
      mcpServers: { a: { command: 'node', args: ['a.js'] } },
      servers: { b: { type: 'http', url: 'https://b.example.com/mcp' } },
      mcp: { servers: { c: { command: 'uvx', args: ['c==1.0.0'] } } },
      mcp_servers: { d: { command: 'npx', args: ['d@1.0.0'] } },
      projects: {
        '/proj': {
          mcpServers: { e: { command: 'node', args: ['e.js'] } },
        },
      },
    };
    const servers = extractServersFromParsedConfig(parsed);
    assert.deepEqual(
      servers.map((s) => s.name),
      ['a', 'b', 'c', 'd', 'e'],
    );
  });
});
