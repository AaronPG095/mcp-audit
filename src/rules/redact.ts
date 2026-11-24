/**
 * Redacts a secret value so raw credentials are never emitted in findings, JSON, or terminal output.
 */
export function redactSecret(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 10) {
    return '[REDACTED]';
  }
  return `${trimmed.slice(0, 4)}...${trimmed.slice(-2)}`;
}

/**
 * Computes Shannon entropy (bits per character) of a string.
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
