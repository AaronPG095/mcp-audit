import { spawn } from 'node:child_process';
import type {
  McpResourceSchema,
  McpServerConfig,
  McpToolSchema,
  ServerInspectionResult,
} from '../types.js';

export const DEFAULT_INSPECT_TIMEOUT_MS = 5000;
const MAX_PAGINATION_PAGES = 10;

export const ALLOWED_READ_ONLY_METHODS = new Set([
  'initialize',
  'notifications/initialized',
  'tools/list',
  'resources/list',
]);

/**
 * Structural guard ensuring mcp-audit can never send tools/call or any mutating RPC method.
 */
export function assertReadOnlyMethod(method: string): void {
  if (!ALLOWED_READ_ONLY_METHODS.has(method)) {
    throw new Error(
      `Refusing non-read-only MCP method "${method}". Only ${Array.from(ALLOWED_READ_ONLY_METHODS).join(', ')} are permitted.`,
    );
  }
}

interface JsonRpcResponse {
  jsonrpc?: string;
  id?: number | string | null;
  result?: unknown;
  error?: { code?: number; message?: string; data?: unknown };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function resolveEnvPlaceholders(value: string, hostEnv: NodeJS.ProcessEnv): string {
  const trimmed = value.trim();
  const braceMatch = trimmed.match(/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/);
  if (braceMatch && braceMatch[1]) {
    return hostEnv[braceMatch[1]] ?? value;
  }
  const dollarMatch = trimmed.match(/^\$([A-Za-z_][A-Za-z0-9_]*)$/);
  if (dollarMatch && dollarMatch[1]) {
    return hostEnv[dollarMatch[1]] ?? value;
  }
  const winMatch = trimmed.match(/^%([A-Za-z_][A-Za-z0-9_]*)%$/);
  if (winMatch && winMatch[1]) {
    return hostEnv[winMatch[1]] ?? value;
  }
  return value;
}

function buildMinimalChildEnv(serverEnv: Record<string, string>): Record<string, string> {
  const safeKeys = [
    'PATH',
    'PATHEXT',
    'SYSTEMROOT',
    'COMSPEC',
    'WINDIR',
    'HOME',
    'USERPROFILE',
    'TEMP',
    'TMP',
    'TMPDIR',
    'LANG',
    'LC_ALL',
    'NODE_ENV',
  ];

  const childEnv: Record<string, string> = {};
  for (const key of safeKeys) {
    const val = process.env[key];
    if (val !== undefined) {
      childEnv[key] = val;
    }
  }

  for (const [k, v] of Object.entries(serverEnv)) {
    childEnv[k] = resolveEnvPlaceholders(v, process.env);
  }

  return childEnv;
}

function normalizeTools(rawTools: unknown): McpToolSchema[] {
  if (!Array.isArray(rawTools)) return [];
  const tools: McpToolSchema[] = [];
  for (const item of rawTools) {
    if (!isRecord(item) || typeof item.name !== 'string') continue;
    tools.push({
      name: item.name,
      description: typeof item.description === 'string' ? item.description : undefined,
      inputSchema: isRecord(item.inputSchema) ? item.inputSchema : undefined,
    });
  }
  return tools;
}

function normalizeResources(rawResources: unknown): McpResourceSchema[] {
  if (!Array.isArray(rawResources)) return [];
  const resources: McpResourceSchema[] = [];
  for (const item of rawResources) {
    if (!isRecord(item) || typeof item.uri !== 'string') continue;
    resources.push({
      uri: item.uri,
      name: typeof item.name === 'string' ? item.name : undefined,
      description: typeof item.description === 'string' ? item.description : undefined,
      mimeType: typeof item.mimeType === 'string' ? item.mimeType : undefined,
    });
  }
  return resources;
}

export async function inspectStdioServer(
  server: McpServerConfig,
  configPath: string,
  timeoutMs = DEFAULT_INSPECT_TIMEOUT_MS,
): Promise<ServerInspectionResult> {
  if (!server.command) {
    return {
      serverName: server.name,
      configPath,
      transport: server.transport,
      status: 'skipped',
      tools: [],
      resources: [],
      error: 'No command specified for stdio server.',
    };
  }

  const child = spawn(server.command, server.args, {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: buildMinimalChildEnv(server.env),
    shell: false,
    windowsHide: true,
  });

  let stderrTail = '';
  child.stderr?.setEncoding('utf8');
  child.stderr?.on('data', (chunk: string) => {
    stderrTail = (stderrTail + chunk).slice(-500);
  });

  const pending = new Map<
    number,
    { resolve: (res: JsonRpcResponse) => void; reject: (err: Error) => void }
  >();
  let nextId = 1;
  let buffer = Buffer.alloc(0);

  const rejectAllPending = (err: Error) => {
    for (const entry of pending.values()) {
      entry.reject(err);
    }
    pending.clear();
  };

  const handleParsedMessage = (msg: unknown) => {
    if (!isRecord(msg)) return;
    const id = msg.id;
    if (typeof id === 'number' && pending.has(id)) {
      const handler = pending.get(id)!;
      pending.delete(id);
      handler.resolve(msg as JsonRpcResponse);
    }
  };

  const drainBuffer = () => {
    while (buffer.length > 0) {
      const asText = buffer.toString('utf8');
      // Check for Content-Length LSP/MCP framing
      const headerMatch = asText.match(/^Content-Length:\s*(\d+)\r?\n\r?\n/i);
      if (headerMatch && headerMatch[1]) {
        const headerByteLen = Buffer.byteLength(headerMatch[0], 'utf8');
        const bodyLen = Number(headerMatch[1]);
        if (buffer.length < headerByteLen + bodyLen) {
          return; // wait for more bytes
        }
        const body = buffer.subarray(headerByteLen, headerByteLen + bodyLen).toString('utf8');
        buffer = buffer.subarray(headerByteLen + bodyLen);
        try {
          handleParsedMessage(JSON.parse(body));
        } catch {
          // ignore malformed non-JSON frame
        }
        continue;
      }

      // Otherwise treat as newline-delimited JSON-RPC
      const nlIdx = buffer.indexOf('\n');
      if (nlIdx === -1) {
        return;
      }
      const line = buffer.subarray(0, nlIdx).toString('utf8').trim();
      buffer = buffer.subarray(nlIdx + 1);
      if (!line) continue;
      try {
        handleParsedMessage(JSON.parse(line));
      } catch {
        // ignore non-JSON stdout noise
      }
    }
  };

  child.stdout?.on('data', (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    drainBuffer();
  });

  child.on('error', (err) => {
    rejectAllPending(new Error(`Failed to spawn server: ${err.message}`));
  });

  child.on('exit', (code, signal) => {
    if (pending.size > 0) {
      rejectAllPending(
        new Error(
          `Server exited prematurely (code=${code ?? 'null'}, signal=${signal ?? 'null'})${
            stderrTail ? `: ${stderrTail.trim()}` : ''
          }`,
        ),
      );
    }
  });

  const sendRequest = (method: string, params?: Record<string, unknown>): Promise<JsonRpcResponse> => {
    assertReadOnlyMethod(method);
    const id = nextId++;
    const payload = JSON.stringify({ jsonrpc: '2.0', id, method, params: params ?? {} }) + '\n';

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`MCP request "${method}" timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      pending.set(id, {
        resolve: (res) => {
          clearTimeout(timer);
          resolve(res);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        },
      });

      if (!child.stdin || child.stdin.destroyed) {
        clearTimeout(timer);
        pending.delete(id);
        reject(new Error('Server stdin is closed'));
        return;
      }

      child.stdin.write(payload, 'utf8');
    });
  };

  const sendNotification = (method: string): void => {
    assertReadOnlyMethod(method);
    if (child.stdin && !child.stdin.destroyed) {
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method }) + '\n', 'utf8');
    }
  };

  try {
    const initRes = await sendRequest('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'mcp-audit', version: '0.2.0' },
    });

    if (initRes.error) {
      throw new Error(initRes.error.message ?? 'initialize failed');
    }

    const initResult = isRecord(initRes.result) ? initRes.result : {};
    const protocolVersion =
      typeof initResult.protocolVersion === 'string' ? initResult.protocolVersion : undefined;
    const serverInfo = isRecord(initResult.serverInfo)
      ? {
          name: typeof initResult.serverInfo.name === 'string' ? initResult.serverInfo.name : undefined,
          version:
            typeof initResult.serverInfo.version === 'string' ? initResult.serverInfo.version : undefined,
        }
      : undefined;

    sendNotification('notifications/initialized');

    const tools: McpToolSchema[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < MAX_PAGINATION_PAGES; page++) {
      const toolsRes = await sendRequest('tools/list', cursor ? { cursor } : {});
      if (toolsRes.error) {
        if (toolsRes.error.code === -32601) break;
        throw new Error(toolsRes.error.message ?? 'tools/list failed');
      }
      const resObj = isRecord(toolsRes.result) ? toolsRes.result : {};
      tools.push(...normalizeTools(resObj.tools));
      cursor = typeof resObj.nextCursor === 'string' && resObj.nextCursor ? resObj.nextCursor : undefined;
      if (!cursor) break;
    }

    const resources: McpResourceSchema[] = [];
    const resourcesRes = await sendRequest('resources/list', {});
    if (!resourcesRes.error && isRecord(resourcesRes.result)) {
      resources.push(...normalizeResources(resourcesRes.result.resources));
    }

    return {
      serverName: server.name,
      configPath,
      transport: server.transport,
      status: 'ok',
      protocolVersion,
      serverInfo,
      tools,
      resources,
    };
  } catch (err) {
    return {
      serverName: server.name,
      configPath,
      transport: server.transport,
      status: 'error',
      tools: [],
      resources: [],
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    try {
      child.stdin?.end();
    } catch {
      // ignore
    }
    try {
      if (!child.killed) {
        child.kill();
      }
    } catch {
      // ignore
    }
  }
}

function parseSseOrJsonRpc(contentType: string, bodyText: string): JsonRpcResponse | null {
  if (contentType.includes('text/event-stream')) {
    const lines = bodyText.split(/\r?\n/);
    let lastParsed: JsonRpcResponse | null = null;
    for (const line of lines) {
      if (!line.startsWith('data:')) continue;
      const payload = line.slice(5).trim();
      if (!payload || payload === '[DONE]') continue;
      try {
        const parsed = JSON.parse(payload);
        if (isRecord(parsed)) {
          lastParsed = parsed as JsonRpcResponse;
        }
      } catch {
        // ignore non-JSON SSE event
      }
    }
    return lastParsed;
  }

  const parsed = JSON.parse(bodyText);
  if (Array.isArray(parsed)) {
    return (parsed[0] as JsonRpcResponse) ?? null;
  }
  return isRecord(parsed) ? (parsed as JsonRpcResponse) : null;
}

export async function inspectHttpServer(
  server: McpServerConfig,
  configPath: string,
  timeoutMs = DEFAULT_INSPECT_TIMEOUT_MS,
): Promise<ServerInspectionResult> {
  if (!server.url) {
    return {
      serverName: server.name,
      configPath,
      transport: server.transport,
      status: 'skipped',
      tools: [],
      resources: [],
      error: 'No URL specified for HTTP/SSE server.',
    };
  }

  let sessionId: string | undefined;
  let nextId = 1;

  const baseHeaders: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
  };
  for (const [k, v] of Object.entries(server.headers)) {
    baseHeaders[k] = resolveEnvPlaceholders(v, process.env);
  }

  const postRpc = async (
    method: string,
    params?: Record<string, unknown>,
    isNotification = false,
  ): Promise<JsonRpcResponse | null> => {
    assertReadOnlyMethod(method);
    const body = isNotification
      ? JSON.stringify({ jsonrpc: '2.0', method })
      : JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params: params ?? {} });

    const headers: Record<string, string> = { ...baseHeaders };
    if (sessionId) {
      headers['mcp-session-id'] = sessionId;
    }

    const res = await fetch(server.url!, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(timeoutMs),
    });

    const returnedSession = res.headers.get('mcp-session-id');
    if (returnedSession) {
      sessionId = returnedSession;
    }

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }

    if (isNotification || res.status === 202) {
      return null;
    }

    const text = await res.text();
    if (!text.trim()) return null;
    return parseSseOrJsonRpc(res.headers.get('content-type') ?? '', text);
  };

  try {
    const initRes = await postRpc('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'mcp-audit', version: '0.2.0' },
    });

    if (initRes?.error) {
      throw new Error(initRes.error.message ?? 'initialize failed');
    }

    const initResult = initRes && isRecord(initRes.result) ? initRes.result : {};
    const protocolVersion =
      typeof initResult.protocolVersion === 'string' ? initResult.protocolVersion : undefined;
    const serverInfo = isRecord(initResult.serverInfo)
      ? {
          name: typeof initResult.serverInfo.name === 'string' ? initResult.serverInfo.name : undefined,
          version:
            typeof initResult.serverInfo.version === 'string' ? initResult.serverInfo.version : undefined,
        }
      : undefined;

    await postRpc('notifications/initialized', undefined, true);

    const toolsRes = await postRpc('tools/list', {});
    if (toolsRes?.error && toolsRes.error.code !== -32601) {
      throw new Error(toolsRes.error.message ?? 'tools/list failed');
    }
    const tools =
      toolsRes && isRecord(toolsRes.result) ? normalizeTools(toolsRes.result.tools) : [];

    const resourcesRes = await postRpc('resources/list', {});
    const resources =
      resourcesRes && !resourcesRes.error && isRecord(resourcesRes.result)
        ? normalizeResources(resourcesRes.result.resources)
        : [];

    return {
      serverName: server.name,
      configPath,
      transport: server.transport,
      status: 'ok',
      protocolVersion,
      serverInfo,
      tools,
      resources,
    };
  } catch (err) {
    return {
      serverName: server.name,
      configPath,
      transport: server.transport,
      status: 'error',
      tools: [],
      resources: [],
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function inspectServer(
  server: McpServerConfig,
  configPath: string,
  timeoutMs = DEFAULT_INSPECT_TIMEOUT_MS,
): Promise<ServerInspectionResult> {
  if (server.transport === 'stdio' || (!server.url && server.command)) {
    return inspectStdioServer(server, configPath, timeoutMs);
  }
  if (server.transport === 'http' || server.transport === 'sse' || server.url) {
    return inspectHttpServer(server, configPath, timeoutMs);
  }
  return {
    serverName: server.name,
    configPath,
    transport: server.transport,
    status: 'skipped',
    tools: [],
    resources: [],
    error: 'Unsupported or unknown MCP transport.',
  };
}
