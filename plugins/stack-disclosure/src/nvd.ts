// Reading NVD's answer to "what CVEs affect this product at this version?"
// (GET /rest/json/cves/2.0?virtualMatchString=<cpe>:<version>). The answer
// is { vulnerabilities: [ { cve: {...} }, ... ] }. Each cve carries its id,
// an English description, CVSS metrics (v3.1, v3.0 or v2), weaknesses (CWEs)
// and references. Only what a finding needs is kept, so the cache stays small.

/** One CVE, as much of it as a finding shows. */
export interface Cve {
  id: string;
  /** CVSS base score, or -1 when NVD gives none. */
  score: number;
  /** CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN. */
  severity: string;
  /** The CVSS vector, or "". */
  vector: string;
  published: string;
  summary: string;
  refs: string[];
  cwes: string[];
}

const MAX_REFS = 6;
const MAX_SUMMARY = 400;

/** The NVD query for one CPE at one version, capped to the results wanted. */
export function nvdUrl(cpe: string, version: string, cap: number): string {
  const match = `cpe:2.3:${cpe}:${encodeURIComponent(version)}`;
  return `https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=${match}&resultsPerPage=${cap}`;
}

/** The NVD page for a CVE. */
export function nvdPage(id: string): string {
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;
}

/** The CVSS band of a base score (CVSS v3 thresholds). */
export function band(score: number): "critical" | "high" | "medium" | "low" {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

/** The finding type id for a score, so criticality shows as the finding's colour. */
export function typeFor(score: number): string {
  return "vuln-" + band(score < 0 ? 0 : score);
}

/**
 * The CVEs in an NVD answer, most severe first and capped; undefined when
 * the answer isn't one.
 */
export function readNvd(reply: unknown, cap: number): Cve[] | undefined {
  if (!reply || typeof reply !== "object" || Array.isArray(reply)) return undefined;
  const list = (reply as Record<string, unknown>).vulnerabilities;
  if (list === undefined) return [];
  if (!Array.isArray(list)) return undefined;
  const out: Cve[] = [];
  for (const entry of list) {
    const cve = entry && typeof entry === "object" ? (entry as Record<string, unknown>).cve : undefined;
    if (!cve || typeof cve !== "object") continue;
    const c = cve as Record<string, unknown>;
    const id = str(c.id);
    if (!id) continue;
    const m = metric(c.metrics);
    out.push({
      id,
      score: m.score,
      severity: m.severity,
      vector: m.vector,
      published: str(c.published).slice(0, 10),
      summary: english(c.descriptions),
      refs: references(c.references),
      cwes: weaknesses(c.weaknesses),
    });
  }
  // Most severe first; on a tie the newer CVE id first.
  out.sort((a, b) => b.score - a.score || (a.id < b.id ? 1 : -1));
  return cap > 0 ? out.slice(0, cap) : out;
}

/** The CVSS metric, preferring v3.1, then v3.0, then v2. */
function metric(metrics: unknown): { score: number; severity: string; vector: string } {
  if (metrics && typeof metrics === "object") {
    const m = metrics as Record<string, unknown>;
    for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
      const arr = m[key];
      if (!Array.isArray(arr) || arr.length === 0) continue;
      const first = (arr[0] && typeof arr[0] === "object" ? arr[0] : {}) as Record<string, unknown>;
      const data = (first.cvssData && typeof first.cvssData === "object" ? first.cvssData : {}) as Record<string, unknown>;
      const score = typeof data.baseScore === "number" ? data.baseScore : Number(data.baseScore);
      if (!isFinite(score)) continue;
      // v3 carries baseSeverity in cvssData; v2 carries it on the metric.
      const severity = str(data.baseSeverity) || str(first.baseSeverity) || band(score).toUpperCase();
      return { score, severity: severity.toUpperCase(), vector: str(data.vectorString) };
    }
  }
  return { score: -1, severity: "UNKNOWN", vector: "" };
}

function english(descriptions: unknown): string {
  if (!Array.isArray(descriptions)) return "";
  for (const d of descriptions) {
    if (d && typeof d === "object" && str((d as Record<string, unknown>).lang) === "en") {
      return str((d as Record<string, unknown>).value).slice(0, MAX_SUMMARY);
    }
  }
  return "";
}

function references(refs: unknown): string[] {
  if (!Array.isArray(refs)) return [];
  const out: string[] = [];
  for (const r of refs) {
    const url = r && typeof r === "object" ? str((r as Record<string, unknown>).url) : "";
    if (url && out.indexOf(url) < 0) out.push(url);
    if (out.length >= MAX_REFS) break;
  }
  return out;
}

function weaknesses(ws: unknown): string[] {
  if (!Array.isArray(ws)) return [];
  const out: string[] = [];
  for (const w of ws) {
    const descs = w && typeof w === "object" ? (w as Record<string, unknown>).description : undefined;
    if (!Array.isArray(descs)) continue;
    for (const d of descs) {
      const v = d && typeof d === "object" ? str((d as Record<string, unknown>).value) : "";
      if (/^CWE-\d+$/.test(v) && out.indexOf(v) < 0) out.push(v);
    }
  }
  return out;
}

function str(v: unknown): string {
  return typeof v === "string" || typeof v === "number" ? String(v).trim() : "";
}
