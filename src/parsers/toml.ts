/**
 * Minimal zero-dependency TOML parser tailored for MCP config files (e.g. Codex config.toml).
 * Supports:
 * - # comments outside strings
 * - [section.sub] and [section."quoted"] table headers
 * - basic ("...") and literal ('...') strings with escapes in basic strings
 * - booleans, numbers
 * - single-line and multiline arrays
 * - inline tables { k = "v", ... }
 */

function stripTomlComment(line: string): string {
  let inBasic = false;
  let inLiteral = false;
  let escaped = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (inBasic) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inBasic = false;
      }
      continue;
    }
    if (inLiteral) {
      if (ch === "'") {
        inLiteral = false;
      }
      continue;
    }
    if (ch === '"') {
      inBasic = true;
    } else if (ch === "'") {
      inLiteral = true;
    } else if (ch === '#') {
      return line.slice(0, i);
    }
  }
  return line;
}

function splitKeyPath(raw: string): string[] {
  const parts: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let escaped = false;

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]!;
    if (quote) {
      if (quote === '"' && escaped) {
        current += ch;
        escaped = false;
      } else if (quote === '"' && ch === '\\') {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '.') {
      const trimmed = current.trim();
      if (trimmed) parts.push(trimmed);
      current = '';
    } else {
      current += ch;
    }
  }
  const trimmed = current.trim();
  if (trimmed) parts.push(trimmed);
  return parts;
}

function findTopLevelEquals(line: string): number {
  let quote: '"' | "'" | null = null;
  let escaped = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (quote) {
      if (quote === '"' && escaped) {
        escaped = false;
      } else if (quote === '"' && ch === '\\') {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '=') {
      return i;
    }
  }
  return -1;
}

function unescapeBasicString(rawInner: string): string {
  let out = '';
  for (let i = 0; i < rawInner.length; i++) {
    const ch = rawInner[i]!;
    if (ch !== '\\') {
      out += ch;
      continue;
    }
    const next = rawInner[++i];
    switch (next) {
      case 'b':
        out += '\b';
        break;
      case 't':
        out += '\t';
        break;
      case 'n':
        out += '\n';
        break;
      case 'f':
        out += '\f';
        break;
      case 'r':
        out += '\r';
        break;
      case '"':
        out += '"';
        break;
      case '\\':
        out += '\\';
        break;
      default:
        out += next ?? '';
    }
  }
  return out;
}

function splitTopLevelItems(inner: string): string[] {
  const items: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let escaped = false;
  let bracketDepth = 0;
  let braceDepth = 0;

  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i]!;
    if (quote) {
      current += ch;
      if (quote === '"' && escaped) {
        escaped = false;
      } else if (quote === '"' && ch === '\\') {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
    } else if (ch === '[') {
      bracketDepth++;
      current += ch;
    } else if (ch === ']') {
      bracketDepth--;
      current += ch;
    } else if (ch === '{') {
      braceDepth++;
      current += ch;
    } else if (ch === '}') {
      braceDepth--;
      current += ch;
    } else if (ch === ',' && bracketDepth === 0 && braceDepth === 0) {
      const trimmed = current.trim();
      if (trimmed) items.push(trimmed);
      current = '';
    } else {
      current += ch;
    }
  }

  const trimmed = current.trim();
  if (trimmed) items.push(trimmed);
  return items;
}

function parseValue(raw: string): unknown {
  const trimmed = raw.trim();
  if (!trimmed) return '';

  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    return unescapeBasicString(trimmed.slice(1, -1));
  }
  if (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2) {
    return trimmed.slice(1, -1);
  }
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;

  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    const inner = trimmed.slice(1, -1).trim();
    if (!inner) return [];
    return splitTopLevelItems(inner).map((item) => parseValue(item));
  }

  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    const inner = trimmed.slice(1, -1).trim();
    const obj: Record<string, unknown> = {};
    if (!inner) return obj;
    for (const pair of splitTopLevelItems(inner)) {
      const eq = findTopLevelEquals(pair);
      if (eq === -1) {
        throw new Error(`Invalid inline table entry in TOML: ${pair}`);
      }
      const keyParts = splitKeyPath(pair.slice(0, eq));
      const val = parseValue(pair.slice(eq + 1));
      setNestedValue(obj, keyParts, val);
    }
    return obj;
  }

  if (/^[+-]?\d+(?:_\d+)*(?:\.\d+(?:_\d+)*)?$/.test(trimmed)) {
    return Number(trimmed.replaceAll('_', ''));
  }

  throw new Error(`Unsupported or invalid TOML value: ${trimmed}`);
}

function isBracketsBalanced(value: string): boolean {
  let quote: '"' | "'" | null = null;
  let escaped = false;
  let bracketDepth = 0;
  let braceDepth = 0;

  for (let i = 0; i < value.length; i++) {
    const ch = value[i]!;
    if (quote) {
      if (quote === '"' && escaped) {
        escaped = false;
      } else if (quote === '"' && ch === '\\') {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '[') {
      bracketDepth++;
    } else if (ch === ']') {
      bracketDepth--;
    } else if (ch === '{') {
      braceDepth++;
    } else if (ch === '}') {
      braceDepth--;
    }
  }
  return bracketDepth <= 0 && braceDepth <= 0 && quote === null;
}

function ensureTable(root: Record<string, unknown>, path: string[]): Record<string, unknown> {
  let cursor: Record<string, unknown> = root;
  for (const segment of path) {
    const existing = cursor[segment];
    if (existing === undefined) {
      const next: Record<string, unknown> = {};
      cursor[segment] = next;
      cursor = next;
    } else if (typeof existing === 'object' && existing !== null && !Array.isArray(existing)) {
      cursor = existing as Record<string, unknown>;
    } else {
      throw new Error(`TOML path conflict at segment "${segment}"`);
    }
  }
  return cursor;
}

function setNestedValue(root: Record<string, unknown>, path: string[], value: unknown): void {
  if (path.length === 0) return;
  const parent = path.length === 1 ? root : ensureTable(root, path.slice(0, -1));
  const leaf = path[path.length - 1]!;
  parent[leaf] = value;
}

export function parseToml(text: string): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  let currentTable = root;
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const clean = stripTomlComment(lines[i]!).trim();
    if (!clean) continue;

    if (clean.startsWith('[') && clean.endsWith(']') && !clean.startsWith('[[')) {
      const header = clean.slice(1, -1).trim();
      if (!header) {
        throw new Error(`Empty TOML table header on line ${i + 1}`);
      }
      const path = splitKeyPath(header);
      currentTable = ensureTable(root, path);
      continue;
    }

    const eqIdx = findTopLevelEquals(clean);
    if (eqIdx === -1) {
      throw new Error(`Invalid TOML syntax on line ${i + 1}: ${clean}`);
    }

    const keyRaw = clean.slice(0, eqIdx).trim();
    let valRaw = clean.slice(eqIdx + 1).trim();

    while (!isBracketsBalanced(valRaw) && i + 1 < lines.length) {
      i++;
      const nextClean = stripTomlComment(lines[i]!).trim();
      if (nextClean) {
        valRaw += ' ' + nextClean;
      }
    }

    if (!isBracketsBalanced(valRaw)) {
      throw new Error(`Unterminated TOML array/table/string for key "${keyRaw}"`);
    }

    const keyParts = splitKeyPath(keyRaw);
    const parsedValue = parseValue(valRaw);
    setNestedValue(currentTable, keyParts, parsedValue);
  }

  return root;
}
