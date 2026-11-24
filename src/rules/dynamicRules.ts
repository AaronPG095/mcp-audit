import type {
  DiscoveredConfig,
  Finding,
  InspectionRule,
  ServerInspectionResult,
} from '../types.js';

interface TextField {
  location: string;
  text: string;
}

function collectSchemaTextFields(inspection: ServerInspectionResult): TextField[] {
  const fields: TextField[] = [];

  for (const tool of inspection.tools) {
    fields.push({ location: `tool "${tool.name}" name`, text: tool.name });
    if (tool.description) {
      fields.push({ location: `tool "${tool.name}" description`, text: tool.description });
    }
    if (tool.inputSchema) {
      collectJsonSchemaDescriptions(
        tool.inputSchema,
        `tool "${tool.name}" inputSchema`,
        fields,
      );
    }
  }

  for (const res of inspection.resources) {
    fields.push({ location: `resource "${res.uri}" uri`, text: res.uri });
    if (res.name) {
      fields.push({ location: `resource "${res.uri}" name`, text: res.name });
    }
    if (res.description) {
      fields.push({ location: `resource "${res.uri}" description`, text: res.description });
    }
  }

  return fields;
}

function collectJsonSchemaDescriptions(
  node: unknown,
  prefix: string,
  out: TextField[],
): void {
  if (typeof node !== 'object' || node === null) return;
  if (Array.isArray(node)) {
    node.forEach((item, idx) => collectJsonSchemaDescriptions(item, `${prefix}[${idx}]`, out));
    return;
  }

  const obj = node as Record<string, unknown>;
  for (const [k, v] of Object.entries(obj)) {
    if (k === 'description' && typeof v === 'string') {
      out.push({ location: `${prefix}.description`, text: v });
    } else if (k === 'title' && typeof v === 'string') {
      out.push({ location: `${prefix}.title`, text: v });
    } else if (typeof v === 'object' && v !== null) {
      collectJsonSchemaDescriptions(v, `${prefix}.${k}`, out);
    }
  }
}

function makeDynamicFinding(
  rule: { id: string; severity: Finding['severity']; title: string },
  config: DiscoveredConfig,
  serverName: string,
  message: string,
  remediation: string,
  evidence?: string,
): Finding {
  return {
    ruleId: rule.id,
    severity: rule.severity,
    title: rule.title,
    message,
    remediation,
    filePath: config.path,
    client: config.client,
    serverName,
    evidence,
  };
}

function snippet(text: string, maxLen = 120): string {
  const compact = text.replace(/\s+/g, ' ').trim();
  return compact.length <= maxLen ? compact : `${compact.slice(0, maxLen)}...`;
}

const OVERRIDE_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  {
    label: 'instruction override',
    regex: /\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions?\b/i,
  },
  {
    label: 'hidden system/important tag',
    regex: /<\s*(?:IMPORTANT|SYSTEM|INSTRUCTION|SECRET|HIDDEN)\s*>/i,
  },
  {
    label: 'concealment directive',
    regex: /\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention|show|reveal|disclose)(?:\s+this)?\s+to\s+the\s+user\b/i,
  },
  {
    label: 'stealth directive',
    regex: /\b(?:hide\s+this\s+from\s+the\s+user|without\s+telling\s+the\s+user|keep\s+this\s+secret\s+from\s+the\s+user)\b/i,
  },
];

// 10. MCP-INJ-001: Prompt-Injection / Concealment Directive
export const rulePromptInjectionDirective: InspectionRule = {
  id: 'MCP-INJ-001',
  severity: 'CRITICAL',
  title: 'Prompt-injection or concealment directive in tool metadata',
  evaluate(inspection, config) {
    if (inspection.status !== 'ok') return [];
    const findings: Finding[] = [];

    for (const field of collectSchemaTextFields(inspection)) {
      for (const pattern of OVERRIDE_PATTERNS) {
        const match = field.text.match(pattern.regex);
        if (match) {
          findings.push(
            makeDynamicFinding(
              this,
              config,
              inspection.serverName,
              `Detected ${pattern.label} in ${field.location}.`,
              'Remove or quarantine this MCP server immediately; tool metadata is attempting to hijack model instructions.',
              `${field.location}: "${snippet(match[0])}"`,
            ),
          );
          break;
        }
      }
    }

    return findings;
  },
};

const EXFIL_PATH_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: 'SSH key/directory reference', regex: /(?:~\/\.ssh\b|id_rsa\b|id_ed25519\b|authorized_keys\b)/i },
  { label: 'AWS credentials reference', regex: /(?:~\/\.aws\/credentials\b|\.aws\/credentials\b)/i },
  { label: 'environment secret exfiltration', regex: /\b(?:read|include|pass|send|exfiltrate|append|copy)\b.{0,40}\b(?:process\.env|\.env\b|api[_\s]?keys?|tokens?|secrets?)\b/i },
  { label: 'sensitive system/client config path', regex: /(?:\/etc\/passwd\b|%APPDATA%|claude_desktop_config\.json\b|mcp_config\.json\b|keychain\b)/i },
];

// 11. MCP-INJ-002: Credential / File Exfiltration Directive
export const ruleExfiltrationDirective: InspectionRule = {
  id: 'MCP-INJ-002',
  severity: 'CRITICAL',
  title: 'Credential or sensitive file exfiltration directive in tool metadata',
  evaluate(inspection, config) {
    if (inspection.status !== 'ok') return [];
    const findings: Finding[] = [];

    for (const field of collectSchemaTextFields(inspection)) {
      for (const pattern of EXFIL_PATH_PATTERNS) {
        const match = field.text.match(pattern.regex);
        if (match) {
          findings.push(
            makeDynamicFinding(
              this,
              config,
              inspection.serverName,
              `Detected ${pattern.label} in ${field.location}.`,
              'Do not trust this server; its tool metadata instructs the model to access or exfiltrate sensitive credentials or files.',
              `${field.location}: "${snippet(match[0])}"`,
            ),
          );
          break;
        }
      }
    }

    return findings;
  },
};

const SHADOWING_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  {
    label: 'cross-tool interception',
    regex: /\bwhenever\s+the\s+user\s+(?:calls|uses|invokes)\s+(?:another|any|the)\s+\w*\s*tool\b/i,
  },
  {
    label: 'pre-call hijacking',
    regex: /\bbefore\s+calling\s+[\w.-]+(?:\s+tool)?,?\s+(?:you\s+must|always)\s+call\b/i,
  },
  {
    label: 'tool replacement directive',
    regex: /\b(?:instead\s+of\s+calling\s+[\w.-]+|override\s+the\s+[\w.-]+\s+tool|redefine\s+the\s+behavior\s+of)\b/i,
  },
];

// 12. MCP-INJ-003: Cross-Tool Shadowing / Hijacking
export const ruleCrossToolShadowing: InspectionRule = {
  id: 'MCP-INJ-003',
  severity: 'HIGH',
  title: 'Cross-tool shadowing or hijacking directive in tool metadata',
  evaluate(inspection, config) {
    if (inspection.status !== 'ok') return [];
    const findings: Finding[] = [];

    for (const field of collectSchemaTextFields(inspection)) {
      for (const pattern of SHADOWING_PATTERNS) {
        const match = field.text.match(pattern.regex);
        if (match) {
          findings.push(
            makeDynamicFinding(
              this,
              config,
              inspection.serverName,
              `Detected ${pattern.label} in ${field.location}.`,
              'Remove this server or isolate it from other tools; its metadata attempts to intercept or redirect calls to other tools.',
              `${field.location}: "${snippet(match[0])}"`,
            ),
          );
          break;
        }
      }
    }

    return findings;
  },
};

function detectHiddenUnicode(text: string): string | null {
  let zeroWidthCount = 0;
  let bidiCount = 0;
  let tagCount = 0;

  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp === undefined) continue;

    if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0xfeff || cp === 0x2060) {
      zeroWidthCount++;
    } else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) {
      bidiCount++;
    } else if (cp >= 0xe0000 && cp <= 0xe007f) {
      tagCount++;
    }
  }

  if (tagCount > 0) {
    return `${tagCount} Unicode Tag character(s) (U+E0000-U+E007F)`;
  }
  if (bidiCount > 0) {
    return `${bidiCount} BiDi override character(s)`;
  }
  if (zeroWidthCount > 0) {
    return `${zeroWidthCount} zero-width character(s)`;
  }
  if (/\n{8,}| {40,}/.test(text)) {
    return 'excessive hidden whitespace padding';
  }
  return null;
}

// 13. MCP-INJ-004: Obfuscated / Hidden Unicode in Metadata
export const ruleHiddenUnicode: InspectionRule = {
  id: 'MCP-INJ-004',
  severity: 'MEDIUM',
  title: 'Obfuscated or hidden Unicode characters in tool metadata',
  evaluate(inspection, config) {
    if (inspection.status !== 'ok') return [];
    const findings: Finding[] = [];

    for (const field of collectSchemaTextFields(inspection)) {
      const hit = detectHiddenUnicode(field.text);
      if (hit) {
        findings.push(
          makeDynamicFinding(
            this,
            config,
            inspection.serverName,
            `Detected ${hit} in ${field.location}.`,
            'Inspect the raw server source for hidden prompt-injection payloads encoded with invisible Unicode or whitespace padding.',
            `${field.location} (${hit})`,
          ),
        );
      }
    }

    return findings;
  },
};

const READ_TOOL_HINT = /\b(?:read|get|list|query|search|fetch_file|cat|dump|export)_(?:file|files|dir|secret|env|db|sql|email|mail|note|notes|key|config)\b|\b(?:read_file|list_directory|query_database|get_secrets)\b/i;
const OUTBOUND_EXEC_TOOL_HINT = /\b(?:http_post|http_request|send_email|post_message|webhook|upload|exec|run_command|shell|bash|powershell|eval)\b/i;

/**
 * Dynamic upgrade for MCP-PRIV-004 when live tools/list schemas confirm sensitive read + outbound/exec capabilities.
 */
export function evaluateDynamicToxicCombination(
  inspections: ServerInspectionResult[],
  config: DiscoveredConfig,
): Finding[] {
  const okInspections = inspections.filter((i) => i.configPath === config.path && i.status === 'ok');
  if (okInspections.length === 0) return [];

  const readTools: string[] = [];
  const outboundExecTools: string[] = [];

  for (const insp of okInspections) {
    for (const tool of insp.tools) {
      const text = `${tool.name} ${tool.description ?? ''}`;
      if (READ_TOOL_HINT.test(text)) {
        readTools.push(`${insp.serverName}:${tool.name}`);
      }
      if (OUTBOUND_EXEC_TOOL_HINT.test(text)) {
        outboundExecTools.push(`${insp.serverName}:${tool.name}`);
      }
    }
  }

  if (readTools.length === 0 || outboundExecTools.length === 0) {
    return [];
  }

  return [
    {
      ruleId: 'MCP-PRIV-004',
      severity: 'HIGH',
      title: 'Confirmed toxic capability combination across inspected MCP tools',
      message: `Inspected tool schemas confirm both sensitive read tools (${readTools.slice(0, 3).join(', ')}) and outbound/exec tools (${outboundExecTools.slice(0, 3).join(', ')}).`,
      remediation:
        'Isolate sensitive read servers from outbound network/shell tools or require explicit user approval for outbound/exec tool calls.',
      filePath: config.path,
      client: config.client,
      serverName: okInspections.map((i) => i.serverName).join(', '),
      evidence: `read=[${readTools.slice(0, 3).join(', ')}], outbound/exec=[${outboundExecTools.slice(0, 3).join(', ')}]`,
    },
  ];
}

export const DYNAMIC_INSPECTION_RULES: InspectionRule[] = [
  rulePromptInjectionDirective,
  ruleExfiltrationDirective,
  ruleCrossToolShadowing,
  ruleHiddenUnicode,
];
