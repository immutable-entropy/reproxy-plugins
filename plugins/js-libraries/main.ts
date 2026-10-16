// js-libraries: records the JavaScript libraries a target serves, and what
// osv.dev knows against each version.
//
// Scripts are read as their responses arrive (traffic.on_response_received,
// filtered in plugin.json to JavaScript content types, so no other
// response ever reaches this code). A library's version is found in two
// places (src/detect.ts): the script's URL (a CDN path such as
// /ajax/libs/jquery/3.5.1/, or a file name such as jquery-3.5.1.min.js),
// and its text (the banner comment a library's builds keep, matched in Go
// with text.scan, and only for the libraries whose name is in the text).
//
// Scripts on the targets' own hosts are read, and so are scripts a target's
// page loads from a public CDN (the second target in plugin.json, which
// lists the CDN hosts): those are judged by the Referer or Origin header
// naming a page a target covers, since the CDN itself is no target. A
// target's jQuery is the target's problem wherever it is served from.
//
// Each version found is one finding (value "jquery@1.12.4"), linked to every
// script it was seen in. A version with all three numbers is then looked up
// on osv.dev, and each advisory against it is a finding of its own (value
// "GHSA-… in jquery@1.12.4") carrying the osv.dev link, the severity and the
// release that fixes it. Notes are written to be the same every time a
// version is seen, so findings merge sightings rather than grow repeated
// notes. osv.dev's answers are kept for a day (storage), so a version is
// asked about once however often it is served.
//
// It sends osv.dev the package name and version, never a target's address,
// and doesn't record the requests in the traffic list.

import { findings, http, log, settings, storage, targets, type Flow, type Hooks, type Location } from "reproxy";
import { exact, fromBody, fromUrl, type Detection } from "./src/detect";
import { compare, osvUrl, query, readAnswer, type Vuln } from "./src/osv";
import { displayName } from "./src/signatures";

const osvAPI = "https://api.osv.dev/v1/query";
/** The global storage key holding osv.dev's answers. */
const cacheKey = "osv_cache";
const cacheTTL = 24 * 60 * 60 * 1000;
const cacheMax = 500;
/** How often a failed osv.dev request is tried in all, and the pause before trying again. */
const attempts = 3;
let retryMs = 2000;

type Answer = { at: number; vulns: Vuln[] };

// Session state, reset by load.
/** Version and script pairs already recorded this run. */
const seen = new Set<string>();
/** osv.dev lookups in flight or answered this run, by package@version. */
const lookups = new Map<string, Promise<Vuln[] | undefined>>();

export function load(_e?: Hooks["plugin.on_load"]): void {
  seen.clear();
  lookups.clear();
}

/** For tests: no pause before trying a request again. */
export function setRetry(ms: number): void {
  retryMs = ms;
}

export function inspectInScope({ flow }: Hooks["traffic.on_response_received"]): Promise<void> {
  return inspect(flow, "");
}

export function inspectFromCDN({ flow }: Hooks["traffic.on_response_received"]): Promise<void> {
  if (settings.get<boolean>("cdn_scripts") === false) return Promise.resolve();
  // With no targets every flow is in scope, so inspectInScope has it.
  if (targets.list().length === 0) return Promise.resolve();
  const page = flow.request.header("Referer") || flow.request.header("Origin") || "";
  if (!page || !targets.match(page)) return Promise.resolve();
  return inspect(flow, page);
}

async function inspect(flow: Flow, page: string): Promise<void> {
  const host = flow.host.toLowerCase().replace(/:\d+$/, "");
  const found = fromUrl(host, flow.path);
  const res = flow.response;
  const max = Math.max(Number(settings.get<number>("max_body_kb")) || 4096, 1) * 1024;
  if (!res.empty && res.size <= max && !res.isBinary()) {
    for (const d of fromBody(res.text())) {
      const same = found.find((f) => f.npm === d.npm && f.version === d.version);
      if (same) same.how += " and script text";
      else found.push(d);
    }
  }
  for (const d of found) {
    try {
      await report(flow, d, page);
    } catch (err) {
      log.error(`${d.npm}@${d.version} in ${flow.url}: ${String(err)}`);
    }
  }
}

async function report(flow: Flow, d: Detection, page: string): Promise<void> {
  const pkg = `${d.npm}@${d.version}`;
  const script = `${flow.scheme}://${flow.host}${flow.path}`;
  if (seen.has(pkg + " " + script)) return;

  const ask = settings.get<boolean>("query_osv") !== false && exact(d.version);
  const vulns = ask ? await lookup(d.npm, d.version) : undefined;
  const link = {
    flowId: flow.id,
    ...(d.inBody ? { location: "response_body" as Location } : {}),
    detail: `found by ${d.how}` + (page ? `; loaded by ${page}` : ""),
  };
  const name = displayName(d.npm);

  await findings.record({
    value: pkg,
    types: ["js-library"],
    notes: libraryNotes(name, d, ask, vulns),
    fields: {
      library: name,
      package: d.npm,
      version: d.version,
      "osv.dev": `https://osv.dev/list?ecosystem=npm&q=${encodeURIComponent(d.npm)}`,
    },
    ...link,
  });
  for (const v of vulns ?? []) {
    await findings.record({
      value: `${v.id} in ${pkg}`,
      types: ["js-vulnerability"],
      notes: vulnNotes(name, d, v),
      fields: {
        "osv.dev": osvUrl(v.id),
        advisory: v.id,
        ...(v.aliases.length ? { aliases: v.aliases.join(", ") } : {}),
        ...(v.severity ? { severity: v.severity } : {}),
        ...(v.cvss ? { cvss: v.cvss } : {}),
        package: d.npm,
        version: d.version,
        fixed_in: v.fixed || "no fixed release named",
        ...(v.published ? { published: v.published } : {}),
      },
      ...link,
    });
  }
  // A version osv.dev couldn't be asked about is recorded again (and asked
  // again) the next time the script is seen.
  if (!ask || vulns !== undefined) {
    seen.add(pkg + " " + script);
    if (seen.size > 5000) seen.clear();
  }
}

// ---- Notes --------------------------------------------------------------------

function libraryNotes(name: string, d: Detection, asked: boolean, vulns: Vuln[] | undefined): string {
  let text = `${name} ${d.version} (the npm package ${d.npm}) is served to the application's pages.`;
  if (!exact(d.version)) {
    return text + ` Only part of the version is known (${d.version}), so osv.dev wasn't asked: check the full version in the script and look it up by hand.`;
  }
  if (!asked) return text + " Looking versions up on osv.dev is turned off in this plugin's settings.";
  if (vulns === undefined) {
    return text + " osv.dev couldn't be asked about this version; it is asked again when the script is next seen.";
  }
  if (vulns.length === 0) return text + " osv.dev lists no known vulnerabilities in this version.";
  text += ` osv.dev lists ${vulns.length} known ${vulns.length === 1 ? "vulnerability" : "vulnerabilities"} in this version, each recorded as a finding of its own:\n`;
  for (const v of vulns) {
    text += `\n- ${v.id}${v.aliases.length ? ` (${v.aliases.join(", ")})` : ""}${v.severity ? `, ${v.severity}` : ""}: ${sentence(v.summary || "no summary")}`;
    text += `${v.fixed ? ` Fixed in ${v.fixed}.` : ""} ${osvUrl(v.id)}`;
  }
  const fixes = vulns.map((v) => v.fixed).filter((f) => f);
  if (fixes.length) {
    const highest = fixes.reduce((a, b) => (compare(a, b) >= 0 ? a : b));
    text += `\n\nUpgrading to ${highest} or later fixes ${fixes.length === vulns.length ? "all of them" : `the ${fixes.length} that name a fixed release`}.`;
  }
  return text;
}

function vulnNotes(name: string, d: Detection, v: Vuln): string {
  let text = `${name} ${d.version} is affected by ${v.id}`;
  if (v.aliases.length) text += ` (${v.aliases.join(", ")})`;
  text += `: ${sentence(v.summary || "osv.dev gives no summary")}`;
  if (v.severity) text += ` osv.dev rates it ${v.severity}.`;
  text += v.fixed ? ` It is fixed in ${name} ${v.fixed}.` : " osv.dev names no release that fixes it for this version.";
  text +=
    " The version alone shows the library is vulnerable, not that the application is: whether it can be exploited" +
    " depends on whether the application uses the affected feature, so check that before reporting it.";
  text += `\n\nDetails: ${osvUrl(v.id)}`;
  return text;
}

/** A summary ending as a sentence does. */
function sentence(s: string): string {
  return /[.!?]$/.test(s) ? s : s + ".";
}

// ---- osv.dev ------------------------------------------------------------------

/** What osv.dev knows against a version, or undefined (logged) when it couldn't be asked. */
function lookup(npm: string, version: string): Promise<Vuln[] | undefined> {
  const key = `${npm}@${version}`;
  let p = lookups.get(key);
  if (!p) {
    p = cached(key).then((hit) => hit ?? ask(npm, version));
    lookups.set(key, p);
    // A failure is forgotten, so the next sighting asks again.
    p.then((v) => {
      if (v === undefined) lookups.delete(key);
    });
  }
  return p;
}

async function cached(key: string): Promise<Vuln[] | undefined> {
  const cache = (await storage.get<Record<string, Answer>>(cacheKey)) || {};
  const hit = cache[key];
  return hit && Date.now() - hit.at < cacheTTL ? hit.vulns : undefined;
}

async function ask(npm: string, version: string): Promise<Vuln[] | undefined> {
  const key = `${npm}@${version}`;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    let res;
    try {
      res = await http.send({
        url: osvAPI,
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: query(npm, version),
      });
    } catch (err) {
      if (attempt < attempts) {
        await sleep(retryMs * attempt);
        continue;
      }
      log.error(`${key}: osv.dev couldn't be reached: ${String(err)}`);
      return undefined;
    }
    if ((res.status === 429 || res.status >= 500) && attempt < attempts) {
      await sleep(retryMs * attempt);
      continue;
    }
    if (!res.ok) {
      log.error(`${key}: osv.dev answered HTTP ${res.status}: ${res.text().slice(0, 200)}`);
      return undefined;
    }
    const vulns = readAnswer(res.json(), npm, version);
    if (vulns === undefined) {
      log.error(`${key}: osv.dev's answer wasn't what it should be: ${res.text().slice(0, 200)}`);
      return undefined;
    }
    await remember(key, vulns);
    return vulns;
  }
  return undefined;
}

/** Keep an answer for a day, dropping stale ones and, past the limit, the oldest. */
async function remember(key: string, vulns: Vuln[]): Promise<void> {
  const now = Date.now();
  const cache = (await storage.get<Record<string, Answer>>(cacheKey)) || {};
  cache[key] = { at: now, vulns };
  const keys = Object.keys(cache)
    .filter((k) => now - cache[k].at < cacheTTL)
    .sort((a, b) => cache[b].at - cache[a].at)
    .slice(0, cacheMax);
  const kept: Record<string, Answer> = {};
  for (const k of keys) kept[k] = cache[k];
  try {
    await storage.set(cacheKey, kept);
  } catch (err) {
    log.warn(`osv.dev's answers couldn't be kept: ${String(err)}`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
