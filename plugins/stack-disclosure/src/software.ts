// Pulling a product and its version out of a stack banner, so a disclosed
// version can be looked up for known vulnerabilities. Pure string work: a
// head is small, so no text.scan is needed.
//
// Banners come in two shapes. One or more "NAME/VERSION" pairs, since a
// Server header often chains several ("Apache/2.4.41 (Unix) OpenSSL/1.1.1d
// PHP/7.4.3") — every pair is pulled out, not just the first. And a single
// "NAME VERSION" ("BigIP 16.1.0"), where the name is followed by a space.

export interface Software {
  /** The product token as the banner wrote it, lower-cased. */
  product: string;
  /** The version string as disclosed. */
  version: string;
}

// NAME/VERSION, where the version starts major.minor so a bare "/1" or a
// path isn't taken for one. A trailing build or letter (OpenSSL's "1.1.1d",
// a distribution's "-1ubuntu2") is kept for cpeVersion to tidy.
const SLASH = /([A-Za-z][A-Za-z0-9._+-]*)\/(\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+~-]*)/g;
// NAME VERSION, anchored at the start of a value ("BigIP 16.1.0").
const SPACED = /^([A-Za-z][A-Za-z0-9._+-]*)\s+v?(\d+\.\d+(?:\.\d+)*[A-Za-z0-9.+~-]*)/;

/** The response headers that carry a product and its version. Lower case. */
export const VERSION_HEADERS = ["server", "via", "x-powered-by", "x-generator", "x-powered-cms", "x-content-powered-by"];

/** Every product/version pair a banner value names, de-duplicated. */
export function parseBanners(value: string): Software[] {
  const out: Software[] = [];
  const seen: Record<string, boolean> = {};
  const add = (product: string, version: string) => {
    const p = product.toLowerCase();
    const key = p + "@" + version;
    if (seen[key]) return;
    seen[key] = true;
    out.push({ product: p, version });
  };
  let m: RegExpExecArray | null;
  SLASH.lastIndex = 0;
  while ((m = SLASH.exec(value))) add(m[1], m[2]);
  // Only try the spaced form when there was no slash form, so a value like
  // "Apache/2.4.41 (Debian)" isn't also read as the product "Apache".
  if (out.length === 0) {
    const s = SPACED.exec(value.trim());
    if (s) add(s[1], s[2]);
  }
  return out;
}

/** The product/version pairs disclosed in a response's head. */
export function softwareInHead(head: string): Software[] {
  const out: Software[] = [];
  const seen: Record<string, boolean> = {};
  const lines = head.split(/\r?\n/);
  for (let i = 1; i < lines.length; i++) {
    const colon = lines[i].indexOf(":");
    if (colon <= 0) continue;
    const name = lines[i].slice(0, colon).trim().toLowerCase();
    if (VERSION_HEADERS.indexOf(name) < 0) continue;
    const value = lines[i].slice(colon + 1).trim();
    for (const s of parseBanners(value)) {
      const key = s.product + "@" + s.version;
      if (seen[key]) continue;
      seen[key] = true;
      out.push(s);
    }
  }
  return out;
}

/** A full version names all of major.minor.patch (16.1.0, 2.4.41, 1.1.1d — not
 *  a two-part release line like "1.18", which NVD can't match precisely). */
export function isFullVersion(version: string): boolean {
  return /^\d+\.\d+\.\d+/.test(version);
}

/**
 * The version in the form a CPE wants: the numeric core and an OpenSSL-style
 * trailing letter, with any distribution or build suffix dropped
 * (7.4.3-1ubuntu2 → 7.4.3, 1.1.1d → 1.1.1d).
 */
export function cpeVersion(version: string): string {
  const m = /^(\d+(?:\.\d+)*[a-z]?)/.exec(version);
  return m ? m[1] : version;
}
