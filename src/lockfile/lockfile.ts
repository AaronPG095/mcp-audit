import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type {
  AuditLockfile,
  DiscoveredConfig,
  Finding,
  LockfileResourceEntry,
  LockfileServerEntry,
  LockfileToolEntry,
  ServerInspectionResult,
} from '../types.js';

export const DEFAULT_LOCKFILE_NAME = 'mcp-audit.lock.json';

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const pairs = keys
    .filter((k) => obj[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
  return `{${pairs.join(',')}}`;
}

export function sha256Text(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export function makeServerLockKey(configPath: string, serverName: string, cwd: string): string {
  const rel = path.relative(cwd, configPath).replaceAll('\\', '/');
  const normalizedPath = rel && !rel.startsWith('..') ? rel : configPath.replaceAll('\\', '/');
  return `${normalizedPath}::${serverName}`;
}

function hashTool(description?: string, inputSchema?: Record<string, unknown>): LockfileToolEntry {
  return {
    descriptionHash: sha256Text(description ?? ''),
    inputSchemaHash: sha256Text(canonicalJson(inputSchema ?? {})),
  };
}

function hashResource(
  name?: string,
  description?: string,
  mimeType?: string,
): LockfileResourceEntry {
  return {
    name,
    descriptionHash: sha256Text(description ?? ''),
    mimeType,
  };
}

export function buildLockfile(
  inspections: ServerInspectionResult[],
  cwd: string,
  toolVersion: string,
): AuditLockfile {
  const servers: Record<string, LockfileServerEntry> = {};

  for (const insp of inspections) {
    if (insp.status !== 'ok') continue;
    const key = makeServerLockKey(insp.configPath, insp.serverName, cwd);

    const tools: Record<string, LockfileToolEntry> = {};
    for (const tool of [...insp.tools].sort((a, b) => a.name.localeCompare(b.name))) {
      tools[tool.name] = hashTool(tool.description, tool.inputSchema);
    }

    const resources: Record<string, LockfileResourceEntry> = {};
    for (const res of [...insp.resources].sort((a, b) => a.uri.localeCompare(b.uri))) {
      resources[res.uri] = hashResource(res.name, res.description, res.mimeType);
    }

    servers[key] = {
      transport: insp.transport,
      tools,
      resources,
    };
  }

  return {
    lockfileVersion: 1,
    generatedAt: new Date().toISOString(),
    toolVersion,
    servers,
  };
}

export function writeLockfile(lockfilePath: string, lockfile: AuditLockfile): void {
  writeFileSync(lockfilePath, `${JSON.stringify(lockfile, null, 2)}\n`, 'utf8');
}

export function readLockfile(lockfilePath: string): AuditLockfile {
  const raw = readFileSync(lockfilePath, 'utf8');
  const parsed = JSON.parse(raw) as AuditLockfile;
  if (!parsed || parsed.lockfileVersion !== 1 || typeof parsed.servers !== 'object') {
    throw new Error(`Invalid mcp-audit lockfile format: ${lockfilePath}`);
  }
  return parsed;
}

function makeDriftFinding(
  config: DiscoveredConfig | undefined,
  fallbackPath: string,
  serverName: string,
  message: string,
  evidence?: string,
): Finding {
  return {
    ruleId: 'MCP-DRIFT-001',
    severity: 'HIGH',
    title: 'MCP server tool or schema drift detected',
    message,
    remediation:
      'Inspect the server changes for rug-pull prompt-injection or unexpected capability expansion before updating the lockfile.',
    filePath: config?.path ?? fallbackPath,
    client: config?.client ?? 'custom',
    serverName,
    evidence,
  };
}

export function diffLockfile(
  lockfile: AuditLockfile,
  inspections: ServerInspectionResult[],
  configs: DiscoveredConfig[],
  cwd: string,
): Finding[] {
  const findings: Finding[] = [];
  const configByPath = new Map(configs.map((c) => [c.path, c]));
  const seenKeys = new Set<string>();

  for (const insp of inspections) {
    if (insp.status !== 'ok') continue;
    const key = makeServerLockKey(insp.configPath, insp.serverName, cwd);
    seenKeys.add(key);
    const config = configByPath.get(insp.configPath);
    const locked = lockfile.servers[key];

    if (!locked) {
      findings.push(
        makeDriftFinding(
          config,
          insp.configPath,
          insp.serverName,
          `Server "${insp.serverName}" is not present in the lockfile (${insp.tools.length} tool(s) exposed).`,
          `new server key: ${key}`,
        ),
      );
      continue;
    }

    const liveToolMap = new Map(insp.tools.map((t) => [t.name, t]));

    for (const [toolName, liveTool] of liveToolMap.entries()) {
      const lockedTool = locked.tools[toolName];
      if (!lockedTool) {
        findings.push(
          makeDriftFinding(
            config,
            insp.configPath,
            insp.serverName,
            `New tool "${toolName}" added since lockfile snapshot.`,
            `added tool: ${toolName}`,
          ),
        );
        continue;
      }

      const liveHashes = hashTool(liveTool.description, liveTool.inputSchema);
      if (liveHashes.descriptionHash !== lockedTool.descriptionHash) {
        findings.push(
          makeDriftFinding(
            config,
            insp.configPath,
            insp.serverName,
            `Tool "${toolName}" description changed since lockfile snapshot (potential rug-pull).`,
            `descriptionHash ${lockedTool.descriptionHash.slice(0, 12)} -> ${liveHashes.descriptionHash.slice(0, 12)}`,
          ),
        );
      }
      if (liveHashes.inputSchemaHash !== lockedTool.inputSchemaHash) {
        findings.push(
          makeDriftFinding(
            config,
            insp.configPath,
            insp.serverName,
            `Tool "${toolName}" inputSchema changed since lockfile snapshot.`,
            `inputSchemaHash ${lockedTool.inputSchemaHash.slice(0, 12)} -> ${liveHashes.inputSchemaHash.slice(0, 12)}`,
          ),
        );
      }
    }

    for (const lockedToolName of Object.keys(locked.tools)) {
      if (!liveToolMap.has(lockedToolName)) {
        findings.push(
          makeDriftFinding(
            config,
            insp.configPath,
            insp.serverName,
            `Tool "${lockedToolName}" was removed since lockfile snapshot.`,
            `removed tool: ${lockedToolName}`,
          ),
        );
      }
    }

    const liveResMap = new Map(insp.resources.map((r) => [r.uri, r]));
    for (const [uri, liveRes] of liveResMap.entries()) {
      const lockedRes = locked.resources[uri];
      if (!lockedRes) {
        findings.push(
          makeDriftFinding(
            config,
            insp.configPath,
            insp.serverName,
            `New resource "${uri}" added since lockfile snapshot.`,
            `added resource: ${uri}`,
          ),
        );
        continue;
      }
      const liveResHash = hashResource(liveRes.name, liveRes.description, liveRes.mimeType);
      if (liveResHash.descriptionHash !== lockedRes.descriptionHash) {
        findings.push(
          makeDriftFinding(
            config,
            insp.configPath,
            insp.serverName,
            `Resource "${uri}" description changed since lockfile snapshot.`,
            `descriptionHash ${lockedRes.descriptionHash.slice(0, 12)} -> ${liveResHash.descriptionHash.slice(0, 12)}`,
          ),
        );
      }
    }

    for (const lockedUri of Object.keys(locked.resources)) {
      if (!liveResMap.has(lockedUri)) {
        findings.push(
          makeDriftFinding(
            config,
            insp.configPath,
            insp.serverName,
            `Resource "${lockedUri}" was removed since lockfile snapshot.`,
            `removed resource: ${lockedUri}`,
          ),
        );
      }
    }
  }

  return findings;
}
