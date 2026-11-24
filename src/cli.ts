#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { runStaticAudit, shouldFailAudit, TOOL_VERSION } from './engine.js';
import { formatJsonReport } from './reporters/json.js';
import { formatTerminalReport } from './reporters/terminal.js';
import type { FailOnThreshold, OutputFormat } from './types.js';

const HELP_TEXT = `mcp-audit v${TOOL_VERSION} — Read-only MCP Security & Permission Auditor

Usage:
  mcp-audit [scan] [options]

Options:
  --cwd <dir>            Project directory to scan (default: current directory)
  --config <path>        Additional MCP config file to scan (repeatable)
  --no-global            Skip user/global client configs (repo + --config only)
  --format <fmt>         Output format: terminal | json (default: terminal)
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
  if (raw === 'json') return 'json';
  throw new Error(`Invalid --format value "${raw}". Expected terminal or json.`);
}

export function runCli(argv: string[]): { exitCode: number; stdout: string; stderr: string } {
  try {
    const parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        cwd: { type: 'string' },
        config: { type: 'string', multiple: true },
        'no-global': { type: 'boolean', default: false },
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
    if (command !== 'scan') {
      return {
        exitCode: 2,
        stdout: '',
        stderr: `Unknown command "${command}". Run "mcp-audit --help" for usage.\n`,
      };
    }

    const format = parseFormat(parsed.values.format);
    const failOn = parseFailOn(parsed.values['fail-on']);

    const result = runStaticAudit({
      cwd: parsed.values.cwd,
      extraConfigs: parsed.values.config,
      includeGlobal: !parsed.values['no-global'],
    });

    const stdout =
      format === 'json'
        ? `${formatJsonReport(result)}\n`
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
  const { exitCode, stdout, stderr } = runCli(process.argv.slice(2));
  if (stdout) process.stdout.write(stdout);
  if (stderr) process.stderr.write(stderr);
  process.exitCode = exitCode;
}
