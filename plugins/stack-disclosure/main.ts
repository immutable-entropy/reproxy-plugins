// stack-disclosure: flags what a response's headers give away about the
// stack the site runs on, and — when the vulnerability check is on — looks
// the disclosed versions up for known vulnerabilities.
//
// Each response is read as it arrives (traffic.on_response_received). Only
// response headers are read: a request's headers come from the browser, not
// from the target, so they say nothing about it. The headers are searched
// (src/disclosures.ts) for the web server and its version, the language,
// framework or CMS, the deployed build, internal host names and private
// addresses, framework session cookies, and debugging aids left on.
//
// None of it is a secret and none is a vulnerability on its own, but it is
// what turns "find a way in" into "look up the CVEs for Apache 2.4.41", so
// each is a finding the tester can act on — and the developer can usually
// switch off with the one setting the notes name. Reading is passive:
// nothing is held, and the scanning happens after the response is forwarded.
//
// The vulnerability check (check_vulnerabilities, off by default) takes that
// last step. When a banner names a full version of a catalogued product
// (src/catalog.ts), the version is looked up on the NVD API (version-precise
// CVEs with CVSS scores, src/nvd.ts) and cross-referenced against CISA's
// Known Exploited Vulnerabilities catalog (src/kev.ts). Each CVE becomes a
// finding graded by its CVSS score; products NVD can't match by version
// (F5 BIG-IP, Confluence) are reported from KEV at the product level. This
// is active work, so it is bounded: a version is asked about once a day
// however often it is seen (answers kept in storage), NVD requests are paced
// to its rate limit, and the product and version — never a target's
// address — are all that is sent.

import { findings, http, log, settings, storage, type FindingDraft, type Flow, type Hooks } from "reproxy";
import { BANNERS, disclosures, type Disclosure } from "./src/disclosures";
import { cpeVersion, isFullVersion, softwareInHead } from "./src/software";
import { lookup, type Mapping } from "./src/catalog";
import { nvdPage, nvdUrl, readNvd, typeFor, type Cve } from "./src/nvd";
import { kevForProduct, kevPage, kevRecord, reduceKev, type KevIndex, type KevRecord } from "./src/kev";

/** The disclosures recorded this run, keyed by value and host, so one is
 *  recorded once per host rather than once per response. */
const seen = new Set<string>();
/** The product@version pairs already looked up this run, so a version seen on
 *  many responses is processed once. */
const checked = new Set<string>();
/** NVD lookups in flight or answered this run, by cpe@version. */
const nvdLookups = new Map<string, Promise<Cve[] | undefined>>();
/** The KEV index, fetched once per run (or read from the day's cache). */
let kevPromise: Promise<KevIndex | undefined> | undefined;

// Caches that survive a restart. NVD answers and the KEV index are kept for a
// day, so the same version (or the 1.8 MiB KEV feed) isn't fetched again.
const nvdCacheKey = "nvd_cache";
const kevCacheKey = "kev_index";
const dayMs = 24 * 60 * 60 * 1000;
const nvdCacheMax = 60;

// How a failed request is retried, and the pause between NVD requests (its
// rate limit is 5 requests per 30 s without a key, 50 with one).
const attempts = 3;
let retryMs = 2000;
let nvdIntervalMs = 6500;

/** Module state is per run, so it is cleared when the plugin loads. */
export function load(): void {
  seen.clear();
  checked.clear();
  nvdLookups.clear();
  kevPromise = undefined;
}

/** For tests: no pause between NVD requests. */
export function setPace(ms: number): void {
  nvdIntervalMs = ms;
}
/** For tests: no pause before a request is retried. */
export function setRetry(ms: number): void {
  retryMs = ms;
}

export async function scanResponse({ flow }: Hooks["traffic.on_response_received"]): Promise<void> {
  const skip = settings.get<string[]>("skip_detectors") ?? [];
  const versionsOnly = settings.get<boolean>("versions_only") === true;
  const maxHits = Math.max(1, Number(settings.get<number>("max_findings")) || 25);

  let recorded = 0;
  for (const d of disclosures(flow.response.head())) {
    if (skip.indexOf(d.detector) >= 0) continue;
    if (versionsOnly && !d.versioned && BANNERS.indexOf(d.detector) >= 0) continue;
    // One record per host: the finding's own links say which requests.
    const key = `${d.value}\u0000${flow.host}`;
    if (seen.has(key)) continue;
    if (seen.size > 10000) seen.clear();
    seen.add(key);
    if (recorded >= maxHits) {
      log.info(`flow ${flow.id}: stopped at ${maxHits} disclosures (see the "Most findings from one response" setting)`);
      break;
    }
    recorded++;
    await findings.record(draft(flow, d));
  }

  if (settings.get<boolean>("check_vulnerabilities") === true) {
    await checkVulns(flow);
  }
}

function draft(flow: Flow, d: Disclosure): FindingDraft {
  return {
    value: d.value,
    types: ["disclosure"],
    // The same on every host, so sightings merge into one finding.
    notes: `${d.label}, in the ${d.key} response header. ${d.note}`,
    fields: { detector: d.detector, header: d.key, ...(d.fields ?? {}) },
    flowId: flow.id,
    location: "response_header" as const,
    // A disclosure is something to hide from an attacker, not from the
    // tester's screen, so it is never recorded hidden.
    detail: d.key,
    hidden: false,
  };
}

// ---- Vulnerability lookup -----------------------------------------------------

/** Look up every full version a catalogued product discloses in the head. */
async function checkVulns(flow: Flow): Promise<void> {
  const requireFull = settings.get<boolean>("require_full_version") !== false;
  const minCvss = Math.max(0, Number(settings.get<number>("min_cvss")) || 0);
  const maxCves = Math.max(1, Number(settings.get<number>("max_cves_per_banner")) || 50);
  const useNvd = settings.get<boolean>("use_nvd") !== false;
  const useKev = settings.get<boolean>("use_kev") !== false;
  if (!useNvd && !useKev) return;

  for (const sw of softwareInHead(flow.response.head())) {
    const map = lookup(sw.product);
    if (!map) continue;
    if (requireFull && !isFullVersion(sw.version)) continue;
    const version = cpeVersion(sw.version);
    const runKey = `${map.name}\u0000${version}`;
    if (checked.has(runKey)) continue;
    checked.add(runKey);
    if (checked.size > 5000) checked.clear();
    try {
      await reportVulns(flow, map, version, { minCvss, maxCves, useNvd, useKev });
    } catch (err) {
      // A lookup that couldn't finish (a network error) is let go, so a
      // later response that discloses the same version tries again.
      checked.delete(runKey);
      log.error(`${map.name} ${version}: ${String(err)}`);
    }
  }
}

interface Opts {
  minCvss: number;
  maxCves: number;
  useNvd: boolean;
  useKev: boolean;
}

async function reportVulns(flow: Flow, map: Mapping, version: string, opts: Opts): Promise<void> {
  const kev = opts.useKev ? await kevIndex() : undefined;

  // A product with a CPE is looked up version-precise on NVD, and each CVE is
  // cross-referenced against KEV to flag the ones exploited in the wild.
  if (map.cpe && opts.useNvd) {
    const cves = await nvdFor(map.cpe, version);
    if (cves === undefined) throw new Error("NVD could not be reached");
    let n = 0;
    for (const cve of cves) {
      if (cve.score >= 0 && cve.score < opts.minCvss) continue;
      if (n >= opts.maxCves) break;
      n++;
      const rec = kev ? kevRecord(kev, cve.id) : undefined;
      await findings.record(cveFinding(flow, map, version, cve, rec));
    }
    if (n === 0) log.debug(`${map.name} ${version}: NVD lists no CVEs at or above the CVSS floor`);
    return;
  }

  // A product with no single CPE (F5 BIG-IP, Confluence): report from KEV at
  // the product level, since KEV covers it where NVD can't match the version.
  if (map.kev && kev) {
    const ids = kevForProduct(kev, map.kev);
    if (ids.length === 0) return;
    await findings.record(kevProductFinding(flow, map, ids, kev, opts.maxCves));
  }
}

/** A finding for one NVD CVE, graded by its CVSS score. */
function cveFinding(flow: Flow, map: Mapping, version: string, cve: Cve, kev: KevRecord | undefined): FindingDraft {
  const scored = cve.score >= 0;
  const grade = scored ? `a ${cve.severity.toLowerCase()} (CVSS ${fmt(cve.score)})` : "an unscored";
  const exploited = kev
    ? ` It is in CISA's Known Exploited Vulnerabilities catalog (added ${kev.added}${kev.due ? `, remediation due ${kev.due}` : ""})` +
      `${kev.ransom ? " and has been used in ransomware campaigns" : ""}, so it is being exploited in the wild — prioritise it.`
    : "";
  const fields: Record<string, string> = {
    product: map.name,
    version,
    cpe: `cpe:2.3:${map.cpe}:${version}`,
    cve: cve.id,
    cvss: scored ? `${fmt(cve.score)} (${cve.severity})` : "none published",
    ...(cve.vector ? { vector: cve.vector } : {}),
    ...(cve.cwes.length ? { cwe: cve.cwes.join(", ") } : {}),
    ...(cve.published ? { published: cve.published } : {}),
    nvd: nvdPage(cve.id),
    ...(kev ? { kev: `actively exploited (CISA KEV, added ${kev.added})` } : {}),
  };
  const notes =
    `${map.name} ${version} is affected by ${cve.id} — ${grade} vulnerability.` +
    `${cve.summary ? " " + sentence(cve.summary) : ""}${exploited}` +
    ` The version was read from a response banner, so confirm the application really runs ${map.name} ${version} and uses` +
    ` the affected feature before reporting it. Remediation: upgrade ${map.name} past the affected version (the NVD page lists` +
    ` the fixed releases). Details: ${nvdPage(cve.id)}${kev ? ` ; CISA KEV: ${kevPage()}` : ""}`;
  return {
    value: `${cve.id} in ${map.name} ${version}`,
    types: [typeFor(cve.score)],
    notes,
    fields,
    flowId: flow.id,
    location: "response_header",
    detail: `${map.name} ${version}`,
    hidden: false,
  };
}

/** A product-level KEV finding for a product NVD can't match by version. */
function kevProductFinding(flow: Flow, map: Mapping, ids: string[], index: KevIndex, cap: number): FindingDraft {
  const recs = ids.map((id) => ({ id, rec: kevRecord(index, id) }));
  recs.sort((a, b) => ((a.rec?.added || "") < (b.rec?.added || "") ? 1 : -1));
  const ransom = recs.some((r) => r.rec?.ransom);
  const shown = recs.slice(0, Math.max(1, cap));

  let notes =
    `${map.name} is in CISA's Known Exploited Vulnerabilities catalog, with ${ids.length} known-exploited ` +
    `${ids.length === 1 ? "vulnerability" : "vulnerabilities"}. A version was disclosed on this response, but KEV does not ` +
    `record affected versions, so confirm whether the running version is affected by each CVE below before reporting. ` +
    `These are being exploited in the wild — treat as urgent.${ransom ? " At least one has been used in ransomware campaigns." : ""}`;
  for (const { id, rec } of shown) {
    notes +=
      `\n- ${id}${rec?.name ? `: ${rec.name}` : ""}` +
      `${rec?.added ? ` (added ${rec.added}${rec.due ? `, due ${rec.due}` : ""})` : ""}` +
      `${rec?.ransom ? " [ransomware]" : ""} — ${nvdPage(id)}`;
  }
  notes += `\n\nCISA KEV catalog: ${kevPage()}`;

  return {
    // The product, not the version: KEV is version-agnostic, so every sighting
    // merges into one finding that gathers the hosts it was seen on.
    value: `${map.name} in CISA KEV`,
    types: ["vuln-kev"],
    notes,
    fields: {
      product: map.name,
      kev_cves: shown.map((r) => r.id).join(", "),
      count: String(ids.length),
      ...(ransom ? { ransomware: "yes" } : {}),
      cisa_kev: kevPage(),
    },
    flowId: flow.id,
    location: "response_header",
    detail: map.name,
    hidden: false,
  };
}

// ---- NVD ----------------------------------------------------------------------

/** What NVD knows against a CPE at a version, or undefined (logged) on failure. */
function nvdFor(cpe: string, version: string): Promise<Cve[] | undefined> {
  const key = `${cpe}@${version}`;
  let p = nvdLookups.get(key);
  if (!p) {
    p = nvdCached(key).then((hit) => hit ?? askNvd(cpe, version, key));
    nvdLookups.set(key, p);
    // A failure is forgotten, so the next sighting asks again.
    p.then((v) => {
      if (v === undefined) nvdLookups.delete(key);
    });
  }
  return p;
}

async function nvdCached(key: string): Promise<Cve[] | undefined> {
  const cache = (await storage.get<Record<string, { at: number; cves: Cve[] }>>(nvdCacheKey)) || {};
  const hit = cache[key];
  return hit && Date.now() - hit.at < dayMs ? hit.cves : undefined;
}

async function askNvd(cpe: string, version: string, key: string): Promise<Cve[] | undefined> {
  const cap = Math.max(1, Number(settings.get<number>("max_cves_per_banner")) || 50);
  const apiKey = settings.get<string>("nvd_api_key") || "";
  const url = nvdUrl(cpe, version, cap);
  const wait = apiKey ? Math.min(nvdIntervalMs, 800) : nvdIntervalMs;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (apiKey) headers.apiKey = apiKey;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    await nvdSlot(wait);
    let res;
    try {
      res = await http.send({ url, method: "GET", headers }, { record: true });
    } catch (err) {
      if (attempt < attempts) {
        await sleep(retryMs * attempt);
        continue;
      }
      log.error(`NVD couldn't be reached for ${key}: ${String(err)}`);
      return undefined;
    }
    if ((res.status === 429 || res.status >= 500) && attempt < attempts) {
      await sleep(retryMs * attempt);
      continue;
    }
    if (!res.ok) {
      log.error(`NVD answered HTTP ${res.status} for ${key}`);
      return undefined;
    }
    const cves = readNvd(res.json(), cap);
    if (cves === undefined) {
      log.error(`NVD's answer wasn't what it should be for ${key}: ${res.text().slice(0, 200)}`);
      return undefined;
    }
    await rememberNvd(key, cves);
    return cves;
  }
  return undefined;
}

/** Keep NVD answers for a day, dropping stale ones and, past the limit, the oldest. */
async function rememberNvd(key: string, cves: Cve[]): Promise<void> {
  const now = Date.now();
  const cache = (await storage.get<Record<string, { at: number; cves: Cve[] }>>(nvdCacheKey)) || {};
  cache[key] = { at: now, cves };
  const keys = Object.keys(cache)
    .filter((k) => now - cache[k].at < dayMs)
    .sort((a, b) => cache[b].at - cache[a].at)
    .slice(0, nvdCacheMax);
  const kept: Record<string, { at: number; cves: Cve[] }> = {};
  for (const k of keys) kept[k] = cache[k];
  try {
    await storage.set(nvdCacheKey, kept);
  } catch (err) {
    log.warn(`NVD's answers couldn't be kept: ${String(err)}`);
  }
}

// NVD's requests are serialised and paced, so a run never bursts past its
// rate limit (a 429 would otherwise lock the key out for 30 s).
let nvdGate: Promise<void> = Promise.resolve();
function nvdSlot(wait: number): Promise<void> {
  const mine = nvdGate.then(() => sleep(wait));
  nvdGate = mine.catch(() => {});
  return mine;
}

// ---- CISA KEV -----------------------------------------------------------------

/** The KEV index, from the day's cache or fetched once; undefined on failure. */
function kevIndex(): Promise<KevIndex | undefined> {
  if (!kevPromise) {
    kevPromise = (async () => (await kevCached()) ?? (await askKev()))();
    kevPromise.then((v) => {
      if (v === undefined) kevPromise = undefined;
    });
  }
  return kevPromise;
}

async function kevCached(): Promise<KevIndex | undefined> {
  const hit = await storage.get<{ at: number; index: KevIndex }>(kevCacheKey);
  return hit && Date.now() - hit.at < dayMs ? hit.index : undefined;
}

async function askKev(): Promise<KevIndex | undefined> {
  const url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  for (let attempt = 1; attempt <= attempts; attempt++) {
    let res;
    try {
      res = await http.send({ url, method: "GET", headers: { Accept: "application/json" } }, { record: true });
    } catch (err) {
      if (attempt < attempts) {
        await sleep(retryMs * attempt);
        continue;
      }
      log.error(`CISA KEV couldn't be reached: ${String(err)}`);
      return undefined;
    }
    if ((res.status === 429 || res.status >= 500) && attempt < attempts) {
      await sleep(retryMs * attempt);
      continue;
    }
    if (!res.ok) {
      log.error(`CISA KEV answered HTTP ${res.status}`);
      return undefined;
    }
    const index = reduceKev(res.json());
    if (index === undefined) {
      log.error(`CISA KEV's feed wasn't what it should be: ${res.text().slice(0, 200)}`);
      return undefined;
    }
    try {
      await storage.set(kevCacheKey, { at: Date.now(), index });
    } catch (err) {
      log.warn(`the CISA KEV index couldn't be kept: ${String(err)}`);
    }
    return index;
  }
  return undefined;
}

// ---- helpers ------------------------------------------------------------------

/** A CVSS score as one decimal place (9 → "9.0", 7.5 → "7.5"). */
function fmt(score: number): string {
  return score.toFixed(1);
}

/** A summary ending as a sentence does. */
function sentence(s: string): string {
  return /[.!?]$/.test(s) ? s : s + ".";
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
