import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseJsonc } from '../src/parsers/jsonc.js';
import { parseToml } from '../src/parsers/toml.js';

describe('JSONC parser', () => {
  it('strips line comments, block comments, and trailing commas while preserving URLs in strings', () => {
    const input = `{
      // Top-level comment
      "servers": {
        /* Block comment */
        "remote": {
          "url": "https://example.com/mcp//v1",
          "note": "keep /* not a comment */ and // this",
        },
      },
    }`;

    const parsed = parseJsonc(input) as { servers: { remote: { url: string; note: string } } };
    assert.equal(parsed.servers.remote.url, 'https://example.com/mcp//v1');
    assert.equal(parsed.servers.remote.note, 'keep /* not a comment */ and // this');
  });

  it('handles escaped quotes inside strings', () => {
    const input = `{
      "msg": "hello \\"world\\" // keep", // strip this
    }`;
    const parsed = parseJsonc(input) as { msg: string };
    assert.equal(parsed.msg, 'hello "world" // keep');
  });
});

describe('TOML parser', () => {
  it('parses tables, quoted sub-keys, arrays, inline tables, and comments', () => {
    const input = `
# Global comment
model = "gpt-5"

[mcp_servers.docs]
command = "uvx"
args = [
  "mcp-docs==0.4.1", # inline comment
  "--workspace",
  "./docs",
]
enabled = true

[mcp_servers."my.server".env]
LOG_LEVEL = 'debug'
`;
    const parsed = parseToml(input) as {
      model: string;
      mcp_servers: {
        docs: { command: string; args: string[]; enabled: boolean };
        'my.server': { env: { LOG_LEVEL: string } };
      };
    };

    assert.equal(parsed.model, 'gpt-5');
    assert.equal(parsed.mcp_servers.docs.command, 'uvx');
    assert.deepEqual(parsed.mcp_servers.docs.args, ['mcp-docs==0.4.1', '--workspace', './docs']);
    assert.equal(parsed.mcp_servers.docs.enabled, true);
    assert.equal(parsed.mcp_servers['my.server'].env.LOG_LEVEL, 'debug');
  });
});
