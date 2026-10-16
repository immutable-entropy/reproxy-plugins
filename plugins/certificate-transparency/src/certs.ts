// The certificates two Certificate Transparency search services know for a
// domain, merged into one set.
//
// crt.sh (GET https://crt.sh/?q=<domain>&output=json) lists one row per
// certificate with the issuer's full DN, the subject CN and the names that
// matched the query (name_value, newline-separated), but not the rest of
// the certificate's SAN list. ctlogs.dev (GET
// https://api.ctlogs.dev/v1/subdomains/<domain>) lists one row per
// certificate with one matching name, the issuer's organisation, the key
// algorithm and how many names the certificate holds in all (san_count).
//
// The two are put together certificate by certificate, keyed on the serial
// number (leading zero bytes dropped: crt.sh keeps them, ctlogs.dev
// doesn't) and the start of validity, which together tell a certificate
// apart even when two CAs reuse a serial. The precertificate and the
// final certificate share both, so they are one certificate here, as they
// are to anyone looking at a site. What each service adds goes into the
// same record: names from either, the issuing CA's name from crt.sh, the
// key algorithm and SAN count from ctlogs.dev, and the full SAN list from
// whichever was asked for it (see detailCandidates). A certificate one
// service has missed is kept all the same: that is the point of asking two.
//
// Everything is checked as it is read: the replies are outside input, and
// a field that isn't what it should be is skipped, not trusted.

import { certName, hostOf, inDomain } from "./names";

export type Source = "crt.sh" | "ctlogs.dev";
export const sources: Source[] = ["crt.sh", "ctlogs.dev"];

export interface Cert {
  /** The serial (minimal lower-case hex) and the start of validity. */
  key: string;
  serial: string;
  /** The issuer's organisation ("Let's Encrypt"). */
  issuer: string;
  /** The issuing CA's common name ("R11"), when known. */
  issuerCN: string;
  /** RFC 3339, UTC, to the second. */
  notBefore: string;
  notAfter: string;
  /** The names known to be on it, lower case; wildcards keep their "*.". */
  names: string[];
  /** How many names it holds in all; 0 while unknown. */
  sanCount: number;
  /** True once names is the whole SAN list. */
  sanComplete: boolean;
  keyAlgo: string;
  crtshId: number;
  ctlogsId: string;
  /** The services that listed it. */
  sources: Source[];
}

export type Certs = Map<string, Cert>;

/** A serial as minimal lower-case hex, or "" if it isn't hex. */
export function normalSerial(v: unknown): string {
  const s = str(v).toLowerCase().replace(/[:\s-]/g, "");
  if (!/^[0-9a-f]+$/.test(s)) return "";
  return s.replace(/^0+(?=.)/, "");
}

/** A timestamp as RFC 3339 UTC to the second, or "" if it isn't one. */
export function normalTime(v: unknown): string {
  const m = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)/.exec(str(v));
  return m ? m[1] + "Z" : "";
}

/**
 * The attributes of a distinguished name, by type. Both services' forms
 * are read: crt.sh's "C=US, O=\"DigiCert, Inc.\", CN=…" and ctlogs.dev's
 * "CN=…,O=DigiCert\, Inc.,C=US".
 */
export function parseDN(dn: string): Record<string, string> {
  const out: Record<string, string> = {};
  let i = 0;
  while (i < dn.length) {
    while (dn[i] === " " || dn[i] === ",") i++;
    const eq = dn.indexOf("=", i);
    if (eq < 0) break;
    const type = dn.slice(i, eq).trim().toUpperCase();
    let v = "";
    i = eq + 1;
    if (dn[i] === '"') {
      for (i++; i < dn.length && dn[i] !== '"'; i++) v += dn[i] === "\\" ? dn[++i] ?? "" : dn[i];
      i++;
    } else {
      for (; i < dn.length && dn[i] !== ","; i++) v += dn[i] === "\\" ? dn[++i] ?? "" : dn[i];
    }
    if (type && !(type in out)) out[type] = v.trim();
  }
  return out;
}

/** The record for a certificate, made on first sight. */
function certFor(into: Certs, serial: string, notBefore: string): Cert {
  const key = serial + "/" + notBefore;
  let c = into.get(key);
  if (!c) {
    c = {
      key, serial, issuer: "", issuerCN: "", notBefore, notAfter: "", names: [], sanCount: 0,
      sanComplete: false, keyAlgo: "", crtshId: 0, ctlogsId: "", sources: [],
    };
    into.set(key, c);
  }
  return c;
}

function addSource(c: Cert, s: Source): void {
  if (c.sources.indexOf(s) < 0) c.sources.push(s);
}

function addName(c: Cert, raw: unknown): void {
  const n = certName(raw);
  if (n && c.names.indexOf(n) < 0) c.names.push(n);
}

/**
 * Merge crt.sh's rows for a domain (all of them, or a slice: a big reply is
 * read a few hundred rows at a time). A row none of whose names is under
 * the domain is skipped: crt.sh matches a query as a suffix, so
 * "example.com" also finds "myexample.com". Returns how many rows were used.
 */
export function readCrtsh(rows: unknown[], domain: string, into: Certs): number {
  let used = 0;
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const r = row as Record<string, unknown>;
    const matched = str(r.name_value).split("\n").map(certName).filter((n): n is string => !!n);
    if (!matched.some((n) => inDomain(n, domain))) continue;
    const serial = normalSerial(r.serial_number);
    const notBefore = normalTime(r.not_before);
    if (!serial || !notBefore) continue;
    const c = certFor(into, serial, notBefore);
    used++;
    addSource(c, "crt.sh");
    for (const n of matched) addName(c, n);
    // The CN is one of the SAN names (the Baseline Requirements say so),
    // and often the one name outside the query on a multi-domain cert.
    addName(c, r.common_name);
    const dn = parseDN(str(r.issuer_name));
    if (!c.issuer) c.issuer = dn.O || dn.CN || "";
    if (!c.issuerCN) c.issuerCN = dn.CN || "";
    if (!c.notAfter) c.notAfter = normalTime(r.not_after);
    if (!c.crtshId && typeof r.id === "number") c.crtshId = r.id;
  }
  return used;
}

/**
 * Merge one page of ctlogs.dev's subdomain search. Returns how many
 * certificates the page held, and the cursor for the next one ("" at the end).
 */
export function readCtlogs(reply: unknown, domain: string, into: Certs): { count: number; next: string } {
  if (!reply || typeof reply !== "object") return { count: 0, next: "" };
  const r = reply as Record<string, unknown>;
  let count = 0;
  for (const row of Array.isArray(r.rows) ? r.rows : []) {
    if (!row || typeof row !== "object") continue;
    const o = row as Record<string, unknown>;
    const name = certName(o.match);
    if (!name || !inDomain(name, domain)) continue;
    const serial = normalSerial(o.serial_hex);
    const notBefore = normalTime(o.not_before);
    if (!serial || !notBefore) continue;
    const c = certFor(into, serial, notBefore);
    count++;
    addSource(c, "ctlogs.dev");
    addName(c, name);
    if (!c.issuer) c.issuer = str(o.issuer);
    if (!c.notAfter) c.notAfter = normalTime(o.not_after);
    if (!c.keyAlgo) c.keyAlgo = str(o.key_algo);
    const n = Number(o.san_count);
    if (Number.isInteger(n) && n > 0 && !c.sanComplete) c.sanCount = n;
    if (!c.ctlogsId) c.ctlogsId = str(o.id);
  }
  const next = r.has_next === true ? str(r.next_cursor) : "";
  return { count, next };
}

/** Put a certificate's full SAN list (and its issuer, when given) on it. */
export function setSANs(c: Cert, names: unknown[], issuerDN = ""): void {
  for (const n of names) addName(c, n);
  c.sanCount = names.length;
  c.sanComplete = true;
  if (issuerDN) {
    const dn = parseDN(issuerDN);
    if (!c.issuer) c.issuer = dn.O || "";
    if (!c.issuerCN) c.issuerCN = dn.CN || "";
  }
}

/** Drop the certificates that had expired by now. */
export function dropExpired(certs: Certs, now: number): void {
  for (const [k, c] of certs) {
    if (c.notAfter && Date.parse(c.notAfter) < now) certs.delete(k);
  }
}

/**
 * Whether a certificate's names outside the domain may be trusted to say
 * something about the target: only when it is known to hold no more than
 * maxSans names. A CDN's or a SaaS host's shared certificate names dozens
 * or hundreds of unrelated customers' hosts.
 */
export function isSmall(c: Cert, maxSans: number): boolean {
  return c.sanCount > 0 && c.sanCount <= maxSans;
}

/**
 * The certificates worth asking for in full, best first, at most limit: the
 * ones that may hold names not seen yet (their SAN count is higher than
 * the names known, or unknown) and aren't known to be shared. Certificates
 * whose known names, issuer and SAN count are the same (an RSA and an
 * ECDSA certificate issued together, a renewal) are probably the same list,
 * so only the newest of each is asked for.
 */
export function detailCandidates(certs: Certs, maxSans: number, limit: number, now: number): Cert[] {
  const list = [...certs.values()].filter(
    (c) => !c.sanComplete && (c.sanCount === 0 || (c.sanCount > c.names.length && c.sanCount <= maxSans)),
  );
  list.sort((a, b) => {
    const va = Date.parse(a.notAfter) >= now ? 1 : 0;
    const vb = Date.parse(b.notAfter) >= now ? 1 : 0;
    if (va !== vb) return vb - va;
    return a.notBefore < b.notBefore ? 1 : a.notBefore > b.notBefore ? -1 : 0;
  });
  const out: Cert[] = [];
  const shapes = new Set<string>();
  for (const c of list) {
    if (out.length >= limit) break;
    const shape = [...c.names].sort().join(" ") + "|" + c.issuer + "|" + c.sanCount;
    if (shapes.has(shape)) continue;
    shapes.add(shape);
    out.push(c);
  }
  return out;
}

/** What the certificates say about one host name. */
export interface NameSummary {
  host: string;
  /** Certificates naming it exactly. */
  certificates: number;
  /** Certificates for "*.host". */
  wildcardCertificates: number;
  /** "Let's Encrypt (R11)", most used first. */
  issuers: string[];
  /** The earliest start of validity, and the latest expiry (YYYY-MM-DD). */
  firstIssued: string;
  latestExpiry: string;
  sources: Source[];
  /** False for a name outside the domain looked up. */
  inDomain: boolean;
  /** For a name outside the domain: the names under it that share a certificate with it. */
  sharedWith: string[];
}

/**
 * Every host name the certificates name, with what they say about it. The
 * names outside the domain come only from certificates isSmall allows.
 */
export function summarize(certs: Certs, domain: string, maxSans: number): Map<string, NameSummary> {
  const out = new Map<string, NameSummary>();
  const issuerUse = new Map<string, Map<string, number>>();
  for (const c of certs.values()) {
    const small = isSmall(c, maxSans);
    const inside = c.names.filter((n) => inDomain(n, domain)).map(hostOf);
    for (const name of c.names) {
      const within = inDomain(name, domain);
      if (!within && !small) continue;
      const host = hostOf(name);
      let s = out.get(host);
      if (!s) {
        s = {
          host, certificates: 0, wildcardCertificates: 0, issuers: [], firstIssued: "", latestExpiry: "",
          sources: [], inDomain: within, sharedWith: [],
        };
        out.set(host, s);
        issuerUse.set(host, new Map());
      }
      if (name.startsWith("*.")) s.wildcardCertificates++;
      else s.certificates++;
      const issuer = issuerLabel(c);
      if (issuer) {
        const use = issuerUse.get(host)!;
        use.set(issuer, (use.get(issuer) || 0) + 1);
      }
      const from = c.notBefore.slice(0, 10);
      const to = c.notAfter.slice(0, 10);
      if (from && (!s.firstIssued || from < s.firstIssued)) s.firstIssued = from;
      if (to && to > s.latestExpiry) s.latestExpiry = to;
      for (const src of c.sources) if (s.sources.indexOf(src) < 0) s.sources.push(src);
      if (!within) for (const h of inside) if (s.sharedWith.indexOf(h) < 0) s.sharedWith.push(h);
    }
  }
  for (const [host, use] of issuerUse) {
    const labels = [...use.entries()].sort((a, b) => b[1] - a[1]).map((e) => e[0]);
    // ctlogs.dev names only the organisation, so a certificate it alone
    // listed says "Google Trust Services" where crt.sh's say "Google Trust
    // Services (WE1)": the bare name adds nothing beside the full one.
    out.get(host)!.issuers = labels.filter((l) => !labels.some((m) => m.startsWith(l + " (")));
  }
  for (const s of out.values()) s.sources.sort();
  return out;
}

/** "Let's Encrypt (R11)", or just the one that is known. */
export function issuerLabel(c: Cert): string {
  if (c.issuer && c.issuerCN && c.issuer !== c.issuerCN) return `${c.issuer} (${c.issuerCN})`;
  return c.issuer || c.issuerCN;
}

/** How many certificates each service listed. */
export function countBySource(certs: Certs): Record<Source, number> {
  const out: Record<Source, number> = { "crt.sh": 0, "ctlogs.dev": 0 };
  for (const c of certs.values()) for (const s of c.sources) out[s]++;
  return out;
}

function str(v: unknown): string {
  return typeof v === "string" || typeof v === "number" ? String(v).trim() : "";
}
