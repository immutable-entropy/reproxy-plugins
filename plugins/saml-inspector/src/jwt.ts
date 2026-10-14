// Decoding a JWT's payload into flat key/value fields, so a finding carries
// the claims a tester wants to read — who the token is for, what it grants,
// and when it expires — without decoding it by hand.
//
// Only the payload is read, and only as data: nothing here verifies the
// signature (an unverified payload is exactly what a tester wants to see).

/** decodeClaims returns a JWT's payload as flat string fields, prefixed
 *  "jwt.", or null if the token isn't a decodable JWT. Time claims (exp, iat,
 *  nbf, auth_time) also get the time spelled out. */
export function decodeClaims(token: string): Record<string, string> | null {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  const payload = decodeSegment(parts[1]);
  if (payload === null) return null;
  let obj: unknown;
  try {
    obj = JSON.parse(payload);
  } catch {
    return null;
  }
  if (obj === null || typeof obj !== "object") return null;

  const out: Record<string, string> = {};
  flatten("jwt", obj, out, 0);
  // Name the algorithm from the header, so an "alg": "none" token stands out.
  const header = decodeSegment(parts[0]);
  if (header) {
    try {
      const h = JSON.parse(header) as Record<string, unknown>;
      if (typeof h.alg === "string") out["jwt.header.alg"] = h.alg;
    } catch {
      /* ignore a bad header */
    }
  }
  return Object.keys(out).length > 0 ? out : null;
}

const timeClaims = new Set(["exp", "iat", "nbf", "auth_time", "updated_at"]);
const maxFields = 60;

function flatten(prefix: string, v: unknown, out: Record<string, string>, depth: number): void {
  if (Object.keys(out).length >= maxFields || depth > 6) return;
  if (Array.isArray(v)) {
    if (v.every((x) => typeof x !== "object" || x === null)) {
      out[prefix] = v.map(String).join(", ");
    } else {
      v.forEach((x, i) => flatten(`${prefix}[${i}]`, x, out, depth + 1));
    }
    return;
  }
  if (v !== null && typeof v === "object") {
    for (const k of Object.keys(v as object)) {
      flatten(`${prefix}.${k}`, (v as Record<string, unknown>)[k], out, depth + 1);
    }
    return;
  }
  const leaf = prefix.slice("jwt.".length);
  if (timeClaims.has(leaf) && typeof v === "number") {
    out[prefix] = `${v} (${new Date(v * 1000).toISOString()})`;
  } else {
    out[prefix] = String(v);
  }
}

/** decodeSegment base64url-decodes one JWT segment to UTF-8 text. */
function decodeSegment(seg: string): string | null {
  let b64 = seg.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}
