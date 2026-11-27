#!/usr/bin/env node
import path from 'node:path';
import { parseArgs } from 'node:util';
import { runAudit, shouldFailAudit, TOOL_VERSION } from './engine.js';
import { DEFAULT_INSPECT_TIMEOUT_MS } from './inspect/client.js';
import { buildLockfile, DEFAULT_LOCKFILE_NAME, writeLockfile } from './lockfile/lockfile.js';
import { formatJsonReport } from './reporters/json.js';
import { formatMarkdownReport } from './reporters/markdown.js';
import { formatSarifReport } from './reporters/sarif.js';
import { formatTerminalReport } from './reporters/terminal.js';
import type { FailOnThreshold, OutputFormat } from './types.js';

const HELP_TEXT = `mcp-audit v${TOOL_VERSION} — Read-only MCP Security & Permission Auditor

Usage:
  mcp-audit [scan|lock|diff] [options]

Commands:
  scan                   Audit MCP configs (default). Add --inspect for live tools/list checks
  lock                   Inspect configured servers (read-only) and write mcp-audit.lock.json
  diff                   Inspect configured servers and fail on schema/description drift vs lockfile

Options:
  --cwd <dir>            Project directory to scan (default: current directory)
  --config <path>        Additional MCP config file to scan (repeatable)
  --no-global            Skip user/global client configs (repo + --config only)
  --inspect              Enable read-only live tools/list + resources/list inspection
  --timeout <ms>         Per-server inspection timeout in ms (default: ${DEFAULT_INSPECT_TIMEOUT_MS})
  --lockfile <path>      Path to lockfile (default: <cwd>/${DEFAULT_LOCKFILE_NAME})
  --ignore-file <path>   Path to suppression file (default: <cwd>/.mcp-audit-ignore.json)
  --no-ignore            Disable loading .mcp-audit-ignore.json suppressions
  --format <fmt>         Output format: terminal | json | sarif | markdown (default: terminal)
  --fail-on <sev>        Exit 1 if findings >= severity: CRITICAL | HIGH | MEDIUM | INFO | none (default: HIGH)
  --no-color             Disable ANSI color output
  -h, --help             Show this help message
  -v, --version          Show version

Exit codes:
  0  No findings at or above --fail-on threshold
  1  One or more findings at or above --fail-on threshold
  2  Invalid CLI usage or runtime error
`;

function parseFailOn(raw: string | undefined): FailOnThreshold {
  if (!raw) return 'HIGH';
  const upper = raw.toUpperCase();
  if (upper === 'NONE') return 'none';
  if (upper === 'CRITICAL' || upper === 'HIGH' || upper === 'MEDIUM' || upper === 'INFO') {
    return upper;
  }
  throw new Error(`Invalid --fail-on value "${raw}". Expected CRITICAL, HIGH, MEDIUM, INFO, or none.`);
}

function parseFormat(raw: string | undefined): OutputFormat {
  if (!raw || raw === 'terminal') return 'terminal';
  if (raw === 'json' || raw === 'sarif' || raw === 'markdown') return raw;
  throw new Error(
    `Invalid --format value "${raw}". Expected terminal, json, sarif, or markdown.`,
  );
}

function parseTimeout(raw: string | undefined): number {
  if (!raw) return DEFAULT_INSPECT_TIMEOUT_MS;
  const num = Number(raw);
  if (!Number.isFinite(num) || num <= 0) {
    throw new Error(`Invalid --timeout value "${raw}". Expected a positive number of milliseconds.`);
  }
  return num;
}

export async function runCli(
  argv: string[],
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  try {
    const parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        cwd: { type: 'string' },
        config: { type: 'string', multiple: true },
        'no-global': { type: 'boolean', default: false },
        inspect: { type: 'boolean', default: false },
        timeout: { type: 'string' },
        lockfile: { type: 'string' },
        'ignore-file': { type: 'string' },
        'no-ignore': { type: 'boolean', default: false },
        format: { type: 'string' },
        'fail-on': { type: 'string' },
        'no-color': { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
        version: { type: 'boolean', short: 'v', default: false },
      },
    });

    if (parsed.values.help) {
      return { exitCode: 0, stdout: HELP_TEXT, stderr: '' };
    }
    if (parsed.values.version) {
      return { exitCode: 0, stdout: `mcp-audit v${TOOL_VERSION}\n`, stderr: '' };
    }

    const command = parsed.positionals[0] ?? 'scan';
    if (command !== 'scan' && command !== 'lock' && command !== 'diff') {
      return {
        exitCode: 2,
        stdout: '',
        stderr: `Unknown command "${command}". Run "mcp-audit --help" for usage.\n`,
      };
    }

    const cwd = parsed.values.cwd ? path.resolve(parsed.values.cwd) : process.cwd();
    const format = parseFormat(parsed.values.format);
    const failOn = parseFailOn(parsed.values['fail-on']);
    const inspectTimeoutMs = parseTimeout(parsed.values.timeout);
    const resolvedLockfile = parsed.values.lockfile
      ? path.resolve(cwd, parsed.values.lockfile)
      : path.join(cwd, DEFAULT_LOCKFILE_NAME);

    if (command === 'lock') {
      const result = await runAudit({
        cwd,
        extraConfigs: parsed.values.config,
        includeGlobal: !parsed.values['no-global'],
        inspect: true,
        inspectTimeoutMs,
      });

      const lockfile = buildLockfile(result.inspections ?? [], cwd, TOOL_VERSION);
      writeLockfile(resolvedLockfile, lockfile);

      if (format === 'json') {
        return {
          exitCode: 0,
          stdout: `${JSON.stringify({ lockfilePath: resolvedLockfile, lockfile, summary: result.summary }, null, 2)}\n`,
          stderr: '',
        };
      }

      const serverCount = Object.keys(lockfile.servers).length;
      const toolCount = Object.values(lockfile.servers).reduce(
        (acc, s) => acc + Object.keys(s.tools).length,
        0,
      );
      return {
        exitCode: 0,
        stdout: `Wrote ${resolvedLockfile} (${serverCount} server(s), ${toolCount} tool(s)).\n`,
        stderr: '',
      };
    }

    const result = await runAudit({
      cwd,
      extraConfigs: parsed.values.config,
      includeGlobal: !parsed.values['no-global'],
      inspect: command === 'diff' ? true : parsed.values.inspect,
      inspectTimeoutMs,
      lockfilePath: command === 'diff' ? resolvedLockfile : parsed.values.lockfile ? resolvedLockfile : undefined,
      ignoreFilePath: parsed.values['ignore-file'],
      noIgnore: parsed.values['no-ignore'],
    });

    const stdout =
      format === 'json'
        ? `${formatJsonReport(result)}\n`
        : format === 'sarif'
          ? `${formatSarifReport(result)}\n`
          : format === 'markdown'
            ? `${formatMarkdownReport(result)}\n`
            : `${formatTerminalReport(result, {
                useColor: parsed.values['no-color'] ? false : undefined,
              })}\n`;

    const exitCode = shouldFailAudit(result.findings, failOn) ? 1 : 0;
    return { exitCode, stdout, stderr: '' };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 2, stdout: '', stderr: `Error: ${message}\n` };
  }
}

// Execute when invoked as CLI entrypoint
const isMain =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  process.argv[1] !== undefined &&
  (process.argv[1].endsWith('cli.js') || process.argv[1].endsWith('cli.ts'));

if (isMain) {
  runCli(process.argv.slice(2)).then(({ exitCode, stdout, stderr }) => {
    if (stdout) process.stdout.write(stdout);
    if (stderr) process.stderr.write(stderr);
    process.exitCode = exitCode;
  });
}
