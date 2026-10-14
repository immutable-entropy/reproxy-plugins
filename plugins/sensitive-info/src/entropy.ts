// Shannon entropy, in bits per character: how random a string looks.
// Real keys score around 4 and above; words and identifiers well below.
export function entropy(s: string): number {
  if (s.length === 0) return 0;
  const counts: Record<string, number> = {};
  for (const c of s) counts[c] = (counts[c] || 0) + 1;
  let bits = 0;
  for (const c in counts) {
    const p = counts[c] / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}
