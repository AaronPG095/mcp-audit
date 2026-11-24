/**
 * Strips JSONC comments (// and /* *\/) and trailing commas before } or ],
 * preserving string literals verbatim, then parses with JSON.parse.
 */
export function stripJsoncCommentsAndTrailingCommas(text: string): string {
  const withoutComments: string[] = [];
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;
  let escaped = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const next = text[i + 1];

    if (inLineComment) {
      if (ch === '\n' || ch === '\r') {
        inLineComment = false;
        withoutComments.push(ch);
      }
      continue;
    }

    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        i++;
      } else if (ch === '\n' || ch === '\r') {
        withoutComments.push(ch);
      }
      continue;
    }

    if (inString) {
      withoutComments.push(ch);
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      withoutComments.push(ch);
      continue;
    }

    if (ch === '/' && next === '/') {
      inLineComment = true;
      i++;
      continue;
    }

    if (ch === '/' && next === '*') {
      inBlockComment = true;
      i++;
      continue;
    }

    withoutComments.push(ch);
  }

  // Second pass: remove trailing commas before `}` or `]` outside strings.
  const input = withoutComments.join('');
  const result: string[] = [];
  inString = false;
  escaped = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;

    if (inString) {
      result.push(ch);
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      result.push(ch);
      continue;
    }

    if (ch === ',') {
      let j = i + 1;
      while (j < input.length && /\s/.test(input[j]!)) {
        j++;
      }
      const nextNonWs = input[j];
      if (nextNonWs === '}' || nextNonWs === ']') {
        // Skip trailing comma
        continue;
      }
    }

    result.push(ch);
  }

  return result.join('');
}

export function parseJsonc(text: string): unknown {
  const cleaned = stripJsoncCommentsAndTrailingCommas(text);
  return JSON.parse(cleaned);
}
