// redact shortens a secret for a log line, so the plugin's log doesn't
// become a second copy of every credential it found.
export function redact(secret: string): string {
  if (secret.length <= 8) return "*".repeat(secret.length);
  return secret.slice(0, 4) + "…" + secret.slice(-2) + ` (${secret.length} chars)`;
}
