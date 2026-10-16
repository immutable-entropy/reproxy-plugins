// certificate-transparency: asks the Certificate Transparency logs which
// TLS certificates have been issued for a target's domain, and puts what
// they say in the Entity Explorer.
//
// Each time a domain (or a "*.domain" wildcard) is added to the targets,
// the plugin searches two services for the certificates naming the domain
// or any name under it: crt.sh and ctlogs.dev. Both are asked every time,
// because each is sometimes down (crt.sh often answers 502 under load) and
// each sometimes lacks certificates the other has. Their answers are
// merged certificate by certificate (src/certs.ts), so what is recorded is
// one picture drawn from both, not two side by side.
//
// Every host name on those certificates goes in the Explorer as a
// discovered host (entities.addHost), attributed to the target, with what
// the certificates say about it in its key/value store: how many name it,
// who issued them, when the first was issued and the last expires, and
// which services listed them. Names no target covers show up under
// Targets → Related.
//
// Related domains: neither search lists a certificate's whole SAN list, so
// the plugin fetches the most recent certificates that may hold more names
// (src/certs.ts, detailCandidates), from ctlogs.dev's certificate record
// or, failing that, the certificate itself from crt.sh (src/der.ts). Names
// on them outside the domain (another brand's domain on the same
// certificate, a staging domain) are added too, and the domain entity they
// fall under is noted on the target's host. A certificate naming more than
// "max_names" hosts is a CDN's or SaaS host's shared one, and its other
// names say nothing about the target, so they are left out.
//
// Lookups are kept per engagement: a domain is looked up once while it is a
// target, again if it is removed and added back, and never twice because
// the app restarted. A lookup only one service answered is remembered as
// half done, and the next change to the targets or the settings asks both
// again; what the second asking adds is merged into the notes (src/notes.ts).
//
// This sends the target's domain name to third parties, which is why the
// plugin is disabled until the user enables it. Requests go straight to
// the services through the upstream chain and aren't recorded in the
// traffic list (one may carry the ctlogs.dev key).

import { entities, http, log, settings, storage, targets, type Hooks, type Response, type Target } from "reproxy";
import {
  countBySource, detailCandidates, dropExpired, readCrtsh, readCtlogs, setSANs, sources, summarize,
  type Cert, type Certs, type NameSummary, type Source,
} from "./src/certs";
import { pemBody, sanDNSNames } from "./src/der";
import { domainOf } from "./src/names";
import { keys, mergeNotes, notesFor } from "./src/notes";

/** The engagement storage key: each domain looked up, and which services answered. */
const doneKey = "looked_up";
/** How many crt.sh rows are read in one turn. */
const rowsPerTurn = 400;

/** Per service: the pause between requests, and the time last sent. */
const pace: Record<Source, { gap: number; last: number }> = {
  "crt.sh": { gap: 2000, last: 0 },
  "ctlogs.dev": { gap: 250, last: 0 },
};
/** How long to wait before trying a failed request again, times the attempt. */
let retryMs = 5000;
const attempts = 3;

// Session state, reset by init.
let chain: Promise<unknown> = Promise.resolve();
const pending = new Set<string>();
/** ctlogs.dev's hourly (or monthly) limit was reached: not asked again until then. */
let ctlogsBlockedUntil = 0;

export function init(_e: Hooks["plugin.on_load"]): void {
  chain = Promise.resolve();
  pending.clear();
  ctlogsBlockedUntil = 0;
  for (const s of sources) pace[s].last = 0;
  // A lifecycle hook must answer quickly, so the lookups run on their own.
  background(targets.list());
}

export function onSettings(_e: Hooks["plugin.on_settings_change"]): void {
  background(targets.list());
}

export function onTargets(e: Hooks["target.on_changed"]): Promise<void> {
  return sync(e.targets);
}

export function onEngagement(_e: Hooks["engagement.on_opened"]): Promise<void> {
  return sync(targets.list());
}

/** For tests: no pauses between requests or before trying again, and a promise of the work queued so far. */
export function setTiming(gapMs: number, retryAfterMs: number): void {
  for (const s of sources) pace[s].gap = gapMs;
  retryMs = retryAfterMs;
}
export function idle(): Promise<unknown> {
  return chain;
}

function background(list: Target[]): void {
  sync(list).catch((err) => log.error(`certificate-transparency: ${String(err)}`));
}

type Done = Record<string, Source[]>;

/**
 * Look up every enabled domain target that both services haven't answered
 * for yet in this engagement, and forget the domains no longer targeted
 * (so adding one back looks it up again).
 */
async function sync(list: Target[]): Promise<void> {
  const wanted: string[] = [];
  for (const t of list) {
    const d = t.enabled ? domainOf(t.kind, t.value) : undefined;
    if (d && wanted.indexOf(d) < 0) wanted.push(d);
  }
  const todo = await enqueue(async () => {
    let done: Done;
    try {
      done = (await storage.engagement.get<Done>(doneKey)) || {};
    } catch {
      return []; // no engagement open: nowhere to put what is found
    }
    const kept: Done = {};
    for (const d of Object.keys(done)) if (wanted.indexOf(d) >= 0) kept[d] = done[d];
    if (Object.keys(kept).length !== Object.keys(done).length) await storage.engagement.set(doneKey, kept);
    return wanted.filter((d) => !pending.has(d) && !sources.every((s) => (kept[d] || []).indexOf(s) >= 0));
  });
  await Promise.all(
    todo.map((d) => {
      pending.add(d);
      return enqueue(() => lookup(d)).finally(() => pending.delete(d));
    }),
  );
}

/** Run fn after everything queued before it: one lookup at a time. */
function enqueue<T>(fn: () => Promise<T>): Promise<T> {
  const run = chain.then(fn);
  chain = run.catch(() => undefined);
  return run;
}

async function lookup(domain: string): Promise<void> {
  const certs: Certs = new Map();
  const [crt, ctl] = await Promise.all([fromCrtsh(domain, certs), fromCtlogs(domain, certs)]);
  const answered = sources.filter((s, i) => [crt, ctl][i]);
  if (answered.length === 0) {
    log.warn(`${domain}: neither crt.sh nor ctlogs.dev could be asked; it will be tried again on the next change to the targets or the settings.`);
    return;
  }
  const now = Date.now();
  if (settings.get<boolean>("include_expired") !== true) dropExpired(certs, now);

  const maxNames = clamp(settings.get<number>("max_names"), 25, 1, 1000);
  const limit = clamp(settings.get<number>("related_lookups"), 20, 0, 200);
  let read = 0;
  for (const c of detailCandidates(certs, maxNames, limit, now)) {
    if (await readInFull(c)) read++;
  }
  try {
    await apply(domain, certs, answered, read);
  } catch (err) {
    log.error(`${domain}: what the CT logs returned couldn't be added to the Explorer: ${String(err)}`);
  }
}

// ---- crt.sh -------------------------------------------------------------------

/** Merge what crt.sh knows of a domain into certs; false (and logged) if it couldn't be asked. */
async function fromCrtsh(domain: string, certs: Certs): Promise<boolean> {
  let url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&deduplicate=Y`;
  if (settings.get<boolean>("include_expired") !== true) url += "&exclude=expired";
  const res = await request("crt.sh", domain, url, {}, 120000);
  if (!res) return false;
  const rows = res.json();
  if (!Array.isArray(rows)) {
    log.error(`${domain}: crt.sh's answer wasn't the list it should be: ${res.text().slice(0, 200)}`);
    return false;
  }
  // A big domain has thousands of rows: read them a slice at a time, so no
  // one turn runs out of time.
  for (let i = 0; i < rows.length; i += rowsPerTurn) {
    if (i > 0) await sleep(0);
    readCrtsh(rows.slice(i, i + rowsPerTurn), domain, certs);
  }
  return true;
}

// ---- ctlogs.dev ---------------------------------------------------------------

const ctlogsAPI = "https://api.ctlogs.dev/v1/";

function ctlogsHeaders(): Record<string, string> {
  const key = String(settings.get<string>("ctlogs_api_key") ?? "").trim();
  return key ? { Authorization: `Bearer ${key}` } : {};
}

/** Merge what ctlogs.dev knows of a domain into certs; false (and logged) if it couldn't be asked. */
async function fromCtlogs(domain: string, certs: Certs): Promise<boolean> {
  const pages = clamp(settings.get<number>("ctlogs_pages"), 5, 1, 100);
  let cursor = "";
  for (let page = 1; page <= pages; page++) {
    const url = ctlogsAPI + "subdomains/" + encodeURIComponent(domain) + (cursor ? `?after=${encodeURIComponent(cursor)}` : "");
    const res = await request("ctlogs.dev", domain, url, ctlogsHeaders(), 30000);
    if (!res) return page > 1; // later pages failing still leaves what the first ones gave
    const body = res.json();
    if (body === undefined) {
      log.error(`${domain}: ctlogs.dev's answer wasn't JSON.`);
      return page > 1;
    }
    cursor = readCtlogs(body, domain, certs).next;
    if (!cursor) return true;
    if (page === pages) log.info(`${domain}: ctlogs.dev has more than ${pages} pages of certificates; raise "ctlogs.dev pages per domain" to read more.`);
  }
  return true;
}

// ---- Whole certificates ---------------------------------------------------------

/**
 * Fetch a certificate's whole SAN list: from ctlogs.dev's record when it
 * listed the certificate, or else (or when that fails) the certificate
 * itself from crt.sh.
 */
async function readInFull(c: Cert): Promise<boolean> {
  if (c.ctlogsId && Date.now() >= ctlogsBlockedUntil) {
    const res = await request("ctlogs.dev", c.serial, ctlogsAPI + "cert/" + encodeURIComponent(c.ctlogsId), ctlogsHeaders(), 30000);
    const body = res?.json<Record<string, unknown>>();
    if (body && Array.isArray(body.san_dns)) {
      setSANs(c, body.san_dns, typeof body.issuer_dn === "string" ? body.issuer_dn : "");
      return true;
    }
  }
  if (c.crtshId) {
    const res = await request("crt.sh", c.serial, `https://crt.sh/?d=${c.crtshId}`, {}, 60000);
    const der = res ? pemBody(res.text()) : undefined;
    const names = der ? sanDNSNames(der) : undefined;
    if (names) {
      setSANs(c, names);
      return true;
    }
    if (res) log.warn(`${c.serial}: the certificate crt.sh returned couldn't be read.`);
  }
  return false;
}

// ---- Requests -----------------------------------------------------------------

/**
 * One GET to a service, paced and tried again while the service says it is
 * busy; undefined (and logged) when it failed. what names the lookup in the log.
 */
async function request(source: Source, what: string, url: string, headers: Record<string, string>, timeoutMs: number): Promise<Response | undefined> {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    if (source === "ctlogs.dev" && Date.now() < ctlogsBlockedUntil) {
      log.warn(`${what}: ctlogs.dev's request limit was reached; it isn't asked again until ${new Date(ctlogsBlockedUntil).toISOString()}.`);
      return undefined;
    }
    const p = pace[source];
    const wait = p.last + p.gap - Date.now();
    if (wait > 0) await sleep(wait);
    p.last = Date.now();
    let res: Response;
    try {
      res = await http.send({ url, headers: { Accept: "application/json", ...headers } }, { timeoutMs });
    } catch (err) {
      if (attempt < attempts) {
        await sleep(retryMs * attempt);
        continue;
      }
      log.error(`${what}: ${source} couldn't be reached: ${String(err)}`);
      return undefined;
    }
    if (res.ok) return res;
    if (res.status === 429) {
      // ctlogs.dev answers 429 both for a request sent while another is in
      // flight (Retry-After: 1) and for a spent hourly or monthly quota
      // (Retry-After: until it resets). Only the first is worth waiting for.
      const after = Number(res.header("Retry-After")) || 0;
      if (after > 30) {
        if (source === "ctlogs.dev") ctlogsBlockedUntil = Date.now() + after * 1000;
        log.warn(`${what}: ${source}'s request limit was reached (HTTP 429; it says to wait ${Math.ceil(after / 60)} minutes).`);
        return undefined;
      }
      if (attempt < attempts) {
        await sleep(Math.max(after * 1000, retryMs * attempt));
        continue;
      }
    } else if (res.status >= 500 && attempt < attempts) {
      await sleep(retryMs * attempt);
      continue;
    }
    if (res.status === 401) {
      log.error(`${source} refused the API key (HTTP 401); check it in this plugin's settings.`);
    } else if (res.status === 403 && source === "ctlogs.dev") {
      log.info(`${what}: ctlogs.dev won't page further without an API key (HTTP 403).`);
    } else {
      log.error(`${what}: ${source} answered HTTP ${res.status}: ${res.text().slice(0, 200)}`);
    }
    return undefined;
  }
  return undefined;
}

// ---- The Explorer -------------------------------------------------------------

/** Put what the certificates say in the Explorer, and remember the domain as looked up. */
async function apply(domain: string, certs: Certs, answered: Source[], read: number): Promise<void> {
  const maxNames = clamp(settings.get<number>("max_names"), 25, 1, 1000);
  const names = summarize(certs, domain, maxNames);
  const complete = answered.length === sources.length;
  const from = attribution(domain, names);
  let added = 0;
  const related = new Set<string>();
  for (const s of names.values()) {
    const res = await entities.addHost({ host: s.host, from, detail: `ct:${s.sources.join("+")}` });
    if (res.created) added++;
    await note(res.entity.key, res.entity.kv, notesFor(s), complete);
    // The registrable domain (the entity the host sits under) of a name
    // that is outside the domain looked up, and not the domain it is under.
    const parent = res.entity.parent;
    if (!s.inDomain && parent && domain !== parent && !domain.endsWith("." + parent)) related.add(parent);
  }

  // A summary of the lookup on the domain's own host.
  const self = await entities.addHost({ host: domain, from });
  const counts = countBySource(certs);
  const relatedKey = "ct.related_domains";
  const lookupNotes: Record<string, string> = {
    "ct.lookup": `${certs.size} certificates naming ${names.size} hosts (crt.sh listed ${counts["crt.sh"]}, ctlogs.dev ${counts["ctlogs.dev"]}; ${read} read in full) on ${new Date().toISOString().slice(0, 10)}`
      + (complete ? "" : `; only ${answered.join(" and ")} answered`),
    [relatedKey]: [...related].sort().join(", "),
  };
  if (!complete && self.entity.kv[relatedKey]) {
    lookupNotes[relatedKey] = mergeNotes({ [keys.sharedWith]: self.entity.kv[relatedKey] }, { [keys.sharedWith]: lookupNotes[relatedKey] })[keys.sharedWith];
  }
  await note(self.entity.key, self.entity.kv, lookupNotes, true);

  const done = (await storage.engagement.get<Done>(doneKey)) || {};
  const had = done[domain] || [];
  done[domain] = sources.filter((s) => had.indexOf(s) >= 0 || answered.indexOf(s) >= 0);
  await storage.engagement.set(doneKey, done);
  log.info(
    `${domain}: ${certs.size} certificates (crt.sh ${counts["crt.sh"]}, ctlogs.dev ${counts["ctlogs.dev"]}) name ${names.size} hosts; ` +
      `${added} were new to the Explorer` + (related.size ? `; related domains: ${[...related].sort().join(", ")}` : "") + ".",
  );
}

/**
 * The URL the discoveries are attributed to: the domain itself when a target
 * covers it, or else the first name found that one does. A host is listed
 * as Related only when what led to it is on a target.
 */
function attribution(domain: string, names: Map<string, NameSummary>): string {
  for (const host of [domain, ...names.keys()]) {
    if (targets.match(`https://${host}/`)) return `https://${host}/`;
  }
  return `https://${domain}/`;
}

/**
 * Write notes on an entity. A complete lookup replaces what an earlier one
 * left (removing what no longer holds); a partial one merges into it.
 */
async function note(key: string, kv: Record<string, string>, fresh: Record<string, string>, complete: boolean): Promise<void> {
  const values = complete ? fresh : mergeNotes(kv, fresh);
  for (const name of Object.keys(values)) {
    if (values[name]) await entities.set(key, name, values[name]);
    else if (kv[name] !== undefined) await entities.unset(key, name);
  }
}

function clamp(v: unknown, dflt: number, min: number, max: number): number {
  const n = Math.floor(Number(v));
  return Math.min(Math.max(Number.isFinite(n) && v !== undefined && v !== null ? n : dflt, min), max);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
