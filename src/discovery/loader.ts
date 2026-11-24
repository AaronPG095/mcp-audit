import { readFileSync, statSync } from 'node:fs';
import { parseJsonc } from '../parsers/jsonc.js';
import { parseToml } from '../parsers/toml.js';
import type {
  CandidateConfigPath,
  DiscoveredConfig,
  McpServerConfig,
  TransportKind,
} from '../types.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toStringRecord(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value)) {
    if (typeof v === 'string') {
      out[k] = v;
    } else if (typeof v === 'number' || typeof v === 'boolean') {
      out[k] = String(v);
    }
  }
  return out;
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === 'string');
}

function inferTransport(raw: Record<string, unknown>, command?: string, url?: string): TransportKind {
  const explicit = typeof raw.type === 'string' ? raw.type.toLowerCase() : typeof raw.transport === 'string' ? raw.transport.toLowerCase() : undefined;
  if (explicit === 'stdio') return 'stdio';
  if (explicit === 'sse') return 'sse';
  if (explicit === 'http' || explicit === 'streamable-http' || explicit === 'streamablehttp') return 'http';
  if (command) return 'stdio';
  if (url) {
    return url.toLowerCase().includes('/sse') ? 'sse' : 'http';
  }
  return 'unknown';
}

function normalizeServerEntry(
  name: string,
  entry: unknown,
  projectPath?: string,
): McpServerConfig | null {
  if (!isRecord(entry)) return null;

  const command = typeof entry.command === 'string' ? entry.command : undefined;
  const args = toStringArray(entry.args);
  const url =
    typeof entry.url === 'string'
      ? entry.url
      : typeof entry.serverUrl === 'string'
        ? entry.serverUrl
        : typeof entry.httpUrl === 'string'
          ? entry.httpUrl
          : undefined;

  const env = toStringRecord(entry.env);
  const headers = {
    ...toStringRecord(entry.headers),
    ...toStringRecord(entry.http_headers),
  };

  const disabled = entry.disabled === true || entry.enabled === false;
  const transport = inferTransport(entry, command, url);

  return {
    name,
    transport,
    command,
    args,
    url,
    env,
    headers,
    disabled,
    projectPath,
    raw: entry,
  };
}

function extractServersFromMap(
  mapValue: unknown,
  servers: McpServerConfig[],
  projectPath?: string,
): void {
  if (!isRecord(mapValue)) return;
  for (const [name, entry] of Object.entries(mapValue)) {
    const normalized = normalizeServerEntry(name, entry, projectPath);
    if (normalized) {
      servers.push(normalized);
    }
  }
}

export function extractServersFromParsedConfig(parsed: unknown): McpServerConfig[] {
  if (!isRecord(parsed)) return [];
  const servers: McpServerConfig[] = [];

  // Standard Claude Desktop / Cursor / Antigravity / Gemini / .mcp.json
  extractServersFromMap(parsed.mcpServers, servers);

  // VS Code mcp.json uses top-level `servers`
  extractServersFromMap(parsed.servers, servers);

  // VS Code settings.json uses `mcp.servers`
  if (isRecord(parsed.mcp)) {
    extractServersFromMap(parsed.mcp.servers, servers);
  }

  // Codex config.toml uses `mcp_servers`
  extractServersFromMap(parsed.mcp_servers, servers);

  // Claude Code ~/.claude.json uses `projects.<path>.mcpServers`
  if (isRecord(parsed.projects)) {
    for (const [projectPath, projectEntry] of Object.entries(parsed.projects)) {
      if (isRecord(projectEntry)) {
        extractServersFromMap(projectEntry.mcpServers, servers, projectPath);
      }
    }
  }

  return servers;
}

export function loadConfigFile(candidate: CandidateConfigPath): DiscoveredConfig | null {
  let isFile = false;
  try {
    const stats = statSync(candidate.path);
    isFile = stats.isFile();
  } catch {
    // Missing or unreadable path -> skip silently unless custom
    if (candidate.scope === 'custom') {
      return {
        path: candidate.path,
        client: candidate.client,
        format: candidate.format,
        scope: candidate.scope,
        exists: false,
        servers: [],
        parseError: `Config file not found: ${candidate.path}`,
      };
    }
    return null;
  }

  if (!isFile) return null;

  try {
    const rawText = readFileSync(candidate.path, 'utf8');
    // Strip UTF-8 BOM if present
    const cleanText = rawText.charCodeAt(0) === 0xfeff ? rawText.slice(1) : rawText;

    let parsed: unknown;
    if (candidate.format === 'toml') {
      parsed = parseToml(cleanText);
    } else if (candidate.format === 'jsonc') {
      parsed = parseJsonc(cleanText);
    } else {
      parsed = JSON.parse(cleanText);
    }

    const servers = extractServersFromParsedConfig(parsed);
    return {
      path: candidate.path,
      client: candidate.client,
      format: candidate.format,
      scope: candidate.scope,
      exists: true,
      servers,
    };
  } catch (err) {
    return {
      path: candidate.path,
      client: candidate.client,
      format: candidate.format,
      scope: candidate.scope,
      exists: true,
      servers: [],
      parseError: err instanceof Error ? err.message : String(err),
    };
  }
}

export function loadAllConfigs(candidates: CandidateConfigPath[]): DiscoveredConfig[] {
  const results: DiscoveredConfig[] = [];
  for (const candidate of candidates) {
    const loaded = loadConfigFile(candidate);
    if (loaded) {
      results.push(loaded);
    }
  }
  return results;
}
