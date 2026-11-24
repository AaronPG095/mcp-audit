import os from 'node:os';
import path from 'node:path';
import type { CandidateConfigPath, ClientKind, ConfigFormat, ScanOptions } from '../types.js';

function joinForPlatform(platform: NodeJS.Platform, ...parts: string[]): string {
  return platform === 'win32' ? path.win32.join(...parts) : path.posix.join(...parts);
}

function resolveForPlatform(platform: NodeJS.Platform, base: string, target: string): string {
  return platform === 'win32' ? path.win32.resolve(base, target) : path.posix.resolve(base, target);
}

function inferFormatFromPath(filePath: string): ConfigFormat {
  const lower = filePath.toLowerCase();
  if (lower.endsWith('.toml')) return 'toml';
  if (lower.endsWith('.jsonc')) return 'jsonc';
  if (
    lower.endsWith('settings.json') ||
    lower.includes('vscode') ||
    lower.includes(`${path.sep}code${path.sep}`) ||
    lower.includes('/code/')
  ) {
    return 'jsonc';
  }
  return 'json';
}

function inferClientFromPath(filePath: string): ClientKind {
  const lower = filePath.toLowerCase().replaceAll('\\', '/');
  if (lower.includes('claude_desktop_config')) return 'claude-desktop';
  if (lower.endsWith('/.claude.json')) return 'claude-code';
  if (lower.includes('.cursor/')) return 'cursor';
  if (lower.includes('.vscode/') || lower.includes('/code/user/')) return 'vscode';
  if (lower.includes('.gemini/antigravity/')) return 'antigravity';
  if (lower.includes('.gemini/')) return 'gemini';
  if (lower.includes('.codex/')) return 'codex';
  return 'custom';
}

export function getCandidateConfigPaths(options: ScanOptions = {}): CandidateConfigPath[] {
  const platform = options.platform ?? process.platform;
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? process.env;
  const homeDir = options.homeDir ?? (platform === 'win32' ? env.USERPROFILE || os.homedir() : env.HOME || os.homedir());
  const includeGlobal = options.includeGlobal ?? true;

  const candidates: CandidateConfigPath[] = [
    {
      path: resolveForPlatform(platform, cwd, '.mcp.json'),
      client: 'repo',
      format: 'json',
      scope: 'repo',
    },
    {
      path: joinForPlatform(platform, cwd, '.cursor', 'mcp.json'),
      client: 'cursor',
      format: 'json',
      scope: 'repo',
    },
    {
      path: joinForPlatform(platform, cwd, '.vscode', 'mcp.json'),
      client: 'vscode',
      format: 'jsonc',
      scope: 'repo',
    },
    {
      path: joinForPlatform(platform, cwd, '.codex', 'config.toml'),
      client: 'codex',
      format: 'toml',
      scope: 'repo',
    },
  ];

  if (includeGlobal) {
    if (platform === 'win32') {
      const appData = env.APPDATA || joinForPlatform(platform, homeDir, 'AppData', 'Roaming');
      candidates.push(
        {
          path: joinForPlatform(platform, appData, 'Claude', 'claude_desktop_config.json'),
          client: 'claude-desktop',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.claude.json'),
          client: 'claude-code',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.cursor', 'mcp.json'),
          client: 'cursor',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, appData, 'Code', 'User', 'mcp.json'),
          client: 'vscode',
          format: 'jsonc',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, appData, 'Code', 'User', 'settings.json'),
          client: 'vscode',
          format: 'jsonc',
          scope: 'global',
          label: 'mcp.servers',
        },
        {
          path: joinForPlatform(platform, homeDir, '.gemini', 'antigravity', 'mcp_config.json'),
          client: 'antigravity',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.gemini', 'settings.json'),
          client: 'gemini',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.codex', 'config.toml'),
          client: 'codex',
          format: 'toml',
          scope: 'global',
        },
      );
    } else if (platform === 'darwin') {
      const appSupport = joinForPlatform(platform, homeDir, 'Library', 'Application Support');
      candidates.push(
        {
          path: joinForPlatform(platform, appSupport, 'Claude', 'claude_desktop_config.json'),
          client: 'claude-desktop',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.claude.json'),
          client: 'claude-code',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.cursor', 'mcp.json'),
          client: 'cursor',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, appSupport, 'Code', 'User', 'mcp.json'),
          client: 'vscode',
          format: 'jsonc',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, appSupport, 'Code', 'User', 'settings.json'),
          client: 'vscode',
          format: 'jsonc',
          scope: 'global',
          label: 'mcp.servers',
        },
        {
          path: joinForPlatform(platform, homeDir, '.gemini', 'antigravity', 'mcp_config.json'),
          client: 'antigravity',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.gemini', 'settings.json'),
          client: 'gemini',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.codex', 'config.toml'),
          client: 'codex',
          format: 'toml',
          scope: 'global',
        },
      );
    } else {
      const xdgConfig = env.XDG_CONFIG_HOME || joinForPlatform(platform, homeDir, '.config');
      candidates.push(
        {
          path: joinForPlatform(platform, xdgConfig, 'Claude', 'claude_desktop_config.json'),
          client: 'claude-desktop',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.claude.json'),
          client: 'claude-code',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.cursor', 'mcp.json'),
          client: 'cursor',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, xdgConfig, 'Code', 'User', 'mcp.json'),
          client: 'vscode',
          format: 'jsonc',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, xdgConfig, 'Code', 'User', 'settings.json'),
          client: 'vscode',
          format: 'jsonc',
          scope: 'global',
          label: 'mcp.servers',
        },
        {
          path: joinForPlatform(platform, homeDir, '.gemini', 'antigravity', 'mcp_config.json'),
          client: 'antigravity',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.gemini', 'settings.json'),
          client: 'gemini',
          format: 'json',
          scope: 'global',
        },
        {
          path: joinForPlatform(platform, homeDir, '.codex', 'config.toml'),
          client: 'codex',
          format: 'toml',
          scope: 'global',
        },
      );
    }
  }

  for (const extra of options.extraConfigs ?? []) {
    const resolved = resolveForPlatform(platform, cwd, extra);
    candidates.push({
      path: resolved,
      client: inferClientFromPath(resolved),
      format: inferFormatFromPath(resolved),
      scope: 'custom',
    });
  }

  // Deduplicate by normalized path (case-insensitive on win32)
  const seen = new Set<string>();
  const deduped: CandidateConfigPath[] = [];
  for (const candidate of candidates) {
    const key = platform === 'win32' ? candidate.path.toLowerCase() : candidate.path;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(candidate);
  }

  return deduped;
}
