// Host names: telling them from addresses and from what isn't a name at
// all, and working out which target domain a name falls under.

/**
 * The domain to look up for a target, or undefined when the target names no
 * single domain: an IP, a CIDR range, a regular expression, or a wildcard
 * other than a leading "*." (which is looked up as the domain under it).
 */
export function domainOf(kind: string, value: string): string | undefined {
  let v = value.trim().toLowerCase();
  if (kind === "wildcard") {
    if (!v.startsWith("*.")) return undefined;
    v = v.slice(2);
  } else if (kind !== "domain") {
    return undefined;
  }
  v = v.replace(/\.$/, "");
  return isHostName(v) && v.indexOf(".") > 0 ? v : undefined;
}

/** A DNS host name: letters, digits, dashes and underscores in dotted labels. */
export function isHostName(s: string): boolean {
  if (s.length === 0 || s.length > 253) return false;
  return s.split(".").every((l) => /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/.test(l)) && !isIP(s);
}

/** An IPv4 or IPv6 address. */
export function isIP(s: string): boolean {
  if (/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(s)) return true;
  return s.indexOf(":") >= 0 && /^[0-9a-f:.]+$/i.test(s) && s.split("::").length <= 2;
}

/**
 * A certificate name made comparable: lower case, no trailing dot. A
 * wildcard keeps its "*."; undefined for anything that is neither a host
 * name nor a one-label wildcard (an email address, an IP, a stray CN).
 */
export function certName(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const n = raw.trim().toLowerCase().replace(/\.$/, "");
  const base = n.startsWith("*.") ? n.slice(2) : n;
  return isHostName(base) && base.indexOf(".") > 0 ? n : undefined;
}

/** The host a certificate name stands for: a wildcard's base name. */
export function hostOf(name: string): string {
  return name.startsWith("*.") ? name.slice(2) : name;
}

/** True when a name (or a wildcard's base name) is the domain or under it. */
export function inDomain(name: string, domain: string): boolean {
  const h = hostOf(name);
  return h === domain || h.endsWith("." + domain);
}
