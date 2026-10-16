// Reading osv.dev's answer to "what is known against this npm package at
// this version?" (POST https://api.osv.dev/v1/query).
//
// The answer is { vulns: [...] }, or {} when nothing is known. Each entry
// is an OSV record (https://ossf.github.io/osv-schema/): an ID (GHSA-…,
// CVE-…), a summary, aliases, a severity, and the affected version ranges,
// from which the release that fixed it for this version is worked out.
// Only what a finding needs is kept, so the cache stays small.

/** One advisory, as much of it as a finding shows. */
export interface Vuln {
  id: string;
  summary: string;
  aliases: string[];
  /** "CRITICAL", "HIGH", "MODERATE", "LOW", or "" when osv.dev gives none. */
  severity: string;
  /** The CVSS vector, when there is one. */
  cvss: string;
  /** The first release that fixes it for the version asked about, or "". */
  fixed: string;
  published: string;
}

/** The page on osv.dev for an advisory. */
export function osvUrl(id: string): string {
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

/** The body of a query for one npm package at one version. */
export function query(npm: string, version: string): string {
  return JSON.stringify({ version, package: { name: npm, ecosystem: "npm" } });
}

/**
 * The advisories in an answer, withdrawn ones left out; undefined when the
 * answer isn't one.
 */
export function readAnswer(reply: unknown, npm: string, version: string): Vuln[] | undefined {
  if (!reply || typeof reply !== "object" || Array.isArray(reply)) return undefined;
  const list = (reply as Record<string, unknown>).vulns;
  if (list === undefined) return [];
  if (!Array.isArray(list)) return undefined;
  const out: Vuln[] = [];
  for (const v of list) {
    if (!v || typeof v !== "object") continue;
    const r = v as Record<string, unknown>;
    const id = str(r.id);
    if (!id || r.withdrawn) continue;
    const db = (r.database_specific && typeof r.database_specific === "object" ? r.database_specific : {}) as Record<string, unknown>;
    let cvss = "";
    if (Array.isArray(r.severity)) {
      for (const s of r.severity) {
        const score = s && typeof s === "object" ? str((s as Record<string, unknown>).score) : "";
        if (score.startsWith("CVSS:")) cvss = score;
      }
    }
    out.push({
      id,
      summary: str(r.summary) || firstSentence(str(r.details)),
      aliases: Array.isArray(r.aliases) ? r.aliases.map(str).filter((a) => a && a !== id) : [],
      severity: str(db.severity).toUpperCase(),
      cvss,
      fixed: fixedFor(r.affected, npm, version),
      published: str(r.published).slice(0, 10),
    });
  }
  // The most severe first, so the list in a library's notes reads in order of urgency.
  const rank = (s: string) => ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"].indexOf(s) >>> 0;
  out.sort((a, b) => rank(a.severity) - rank(b.severity) || (a.id < b.id ? -1 : 1));
  return out;
}

/**
 * The release that fixes a version, from an advisory's affected ranges:
 * the "fixed" event closing the range the version falls in.
 */
export function fixedFor(affected: unknown, npm: string, version: string): string {
  if (!Array.isArray(affected)) return "";
  for (const a of affected) {
    if (!a || typeof a !== "object") continue;
    const pkg = (a as Record<string, unknown>).package as Record<string, unknown> | undefined;
    if (!pkg || str(pkg.ecosystem) !== "npm" || str(pkg.name) !== npm) continue;
    const ranges = (a as Record<string, unknown>).ranges;
    if (!Array.isArray(ranges)) continue;
    for (const range of ranges) {
      const events = range && typeof range === "object" ? (range as Record<string, unknown>).events : undefined;
      if (!Array.isArray(events)) continue;
      let introduced = "";
      for (const e of events) {
        if (!e || typeof e !== "object") continue;
        const ev = e as Record<string, unknown>;
        if (ev.introduced !== undefined) introduced = str(ev.introduced);
        const fixed = str(ev.fixed);
        if (fixed && (introduced === "0" || introduced === "" || compare(version, introduced) >= 0) && compare(version, fixed) < 0) {
          return fixed;
        }
      }
    }
  }
  return "";
}

/** Compare two semantic versions: negative, zero or positive. */
export function compare(a: string, b: string): number {
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) if (pa.nums[i] !== pb.nums[i]) return pa.nums[i] - pb.nums[i];
  // A pre-release comes before the release itself.
  if (!pa.pre || !pb.pre) return pa.pre ? -1 : pb.pre ? 1 : 0;
  const xa = pa.pre.split(".");
  const xb = pb.pre.split(".");
  for (let i = 0; i < Math.max(xa.length, xb.length); i++) {
    if (xa[i] === undefined) return -1;
    if (xb[i] === undefined) return 1;
    const na = /^\d+$/.test(xa[i]);
    const nb = /^\d+$/.test(xb[i]);
    if (na && nb && Number(xa[i]) !== Number(xb[i])) return Number(xa[i]) - Number(xb[i]);
    if (na !== nb) return na ? -1 : 1;
    if (xa[i] !== xb[i]) return xa[i] < xb[i] ? -1 : 1;
  }
  return 0;
}

function parse(v: string): { nums: number[]; pre: string } {
  const [core, ...rest] = v.replace(/^v/, "").split("+")[0].split("-");
  const nums = core.split(".").map((n) => Number(n) || 0);
  while (nums.length < 3) nums.push(0);
  return { nums, pre: rest.join("-") };
}

function firstSentence(s: string): string {
  const line = s.split("\n").find((l) => l.trim()) ?? "";
  const end = line.search(/\.\s/);
  return (end > 0 ? line.slice(0, end + 1) : line).slice(0, 200).trim();
}

function str(v: unknown): string {
  return typeof v === "string" || typeof v === "number" ? String(v).trim() : "";
}
