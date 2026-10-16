// Reading DNSDumpster's domain lookup (GET https://api.dnsdumpster.com/domain/<name>).
//
// The reply groups DNS records by type. "a", "mx" and "ns" are lists of
// { host, ips: [{ ip, asn, asn_name, country, ptr, ... }] }; "cname" is
// documented only by an empty example, so it is read defensively (an object
// naming a host, or a bare string); "txt" is a list of strings, which is of
// no use here. Everything is checked as it is read: the reply is outside
// input, and a field that isn't what it should be is skipped, not trusted.

/** The record types a lookup lists names under. */
export type RecordType = "a" | "cname" | "mx" | "ns";

/** A host name the lookup returned. */
export interface Name {
  name: string;
  /** Every record type it appeared under, in the order first seen. */
  types: RecordType[];
  /** The addresses it resolved to. */
  ips: string[];
}

/** An address the lookup returned, with what DNSDumpster knows of it. */
export interface Address {
  ip: string;
  asn: string;
  asnName: string;
  country: string;
  ptr: string;
  /** The names that resolved to it. */
  names: string[];
}

/** What one or more pages of a lookup held. */
export interface Lookup {
  names: Map<string, Name>;
  ips: Map<string, Address>;
}

/** Which record types to keep. A records are always kept. */
export interface Options {
  cname: boolean;
  mx: boolean;
  ns: boolean;
}

export function emptyLookup(): Lookup {
  return { names: new Map(), ips: new Map() };
}

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
 * Merge one page of a reply into what earlier pages gave. Returns how many
 * names and addresses the page added.
 */
export function readPage(reply: unknown, opts: Options, into: Lookup): number {
  if (!reply || typeof reply !== "object") return 0;
  const r = reply as Record<string, unknown>;
  const before = into.names.size + into.ips.size;
  const groups: [RecordType, boolean][] = [["a", true], ["cname", opts.cname], ["mx", opts.mx], ["ns", opts.ns]];
  for (const [type, wanted] of groups) {
    const list = r[type];
    if (!wanted || !Array.isArray(list)) continue;
    for (const rec of list) readRecord(rec, type, into);
  }
  return into.names.size + into.ips.size - before;
}

function readRecord(rec: unknown, type: RecordType, into: Lookup): void {
  let host: unknown;
  let ips: unknown;
  if (typeof rec === "string") {
    host = rec;
  } else if (rec && typeof rec === "object") {
    const o = rec as Record<string, unknown>;
    host = o.host ?? o.target ?? o.cname;
    ips = o.ips;
  }
  const name = typeof host === "string" ? host.trim().toLowerCase().replace(/\.$/, "") : "";
  if (!isHostName(name)) return;
  let n = into.names.get(name);
  if (!n) {
    n = { name, types: [], ips: [] };
    into.names.set(name, n);
  }
  if (n.types.indexOf(type) < 0) n.types.push(type);
  if (!Array.isArray(ips)) return;
  for (const entry of ips) {
    if (!entry || typeof entry !== "object") continue;
    const e = entry as Record<string, unknown>;
    const ip = str(e.ip).toLowerCase();
    if (!isIP(ip)) continue;
    if (n.ips.indexOf(ip) < 0) n.ips.push(ip);
    let a = into.ips.get(ip);
    if (!a) {
      a = { ip, asn: str(e.asn), asnName: str(e.asn_name), country: str(e.country), ptr: str(e.ptr), names: [] };
      into.ips.set(ip, a);
    }
    if (a.names.indexOf(name) < 0) a.names.push(name);
  }
}

function str(v: unknown): string {
  return typeof v === "string" || typeof v === "number" ? String(v).trim() : "";
}
