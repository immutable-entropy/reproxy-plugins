// dnsdumpster: asks DNSDumpster what else is known under a target's domain,
// and lists what it finds under Targets → Related.
//
// Each time a domain (or a "*.domain" wildcard) is added to the targets, the
// plugin looks the domain up with DNSDumpster's API: the host names it has
// seen in the domain's A, CNAME, MX and NS records, and the addresses they
// resolve to. Each name and address is put in the Entity Explorer as a
// discovered host (entities.addHost: a name or address on its own, no
// scheme guessed), with the name's addresses recorded as what it resolves
// to. Each is attributed to the target, so the ones no target covers show
// up under Targets → Related, where the user can promote them. What else
// DNSDumpster knows (the record types; an address's ASN, country and
// reverse name) is left in the host's key/value store.
//
// Lookups are kept per engagement: a domain is looked up once while it is a
// target, again if it is removed and added back, and never twice because
// the app restarted or the engagement was reopened. A lookup that fails (no
// key, a rejected key, the service down) isn't remembered, so the next
// change to the targets or the settings tries again.
//
// This sends the target's domain name to a third party, which is why the
// plugin is disabled until the user enables it. The requests go straight to
// api.dnsdumpster.com through the upstream chain, and are not recorded in
// the traffic list: they carry the API key.

import { entities, http, log, settings, storage, targets, type Hooks, type Target } from "reproxy";
import { domainOf, emptyLookup, readPage, type Lookup } from "./src/records";

const api = "https://api.dnsdumpster.com/domain/";
/** The engagement storage key holding the domains already looked up. */
const doneKey = "looked_up";
/** DNSDumpster allows one request every 2 seconds. */
let gapMs = 2100;
/** How often a rate-limited request is tried in all. */
const attempts = 3;

// Session state, reset by init.
let lastSend = 0;
let chain: Promise<unknown> = Promise.resolve();
const pending = new Set<string>();
let warnedNoKey = false;

export function init(_e: Hooks["plugin.on_load"]): void {
  lastSend = 0;
  chain = Promise.resolve();
  pending.clear();
  warnedNoKey = false;
  // A lifecycle hook must answer quickly, so the lookups run on their own.
  background(targets.list());
}

export function onSettings(_e: Hooks["plugin.on_settings_change"]): void {
  // A key that was missing or wrong may be right now.
  warnedNoKey = false;
  background(targets.list());
}

export function onTargets(e: Hooks["target.on_changed"]): Promise<void> {
  return sync(e.targets);
}

export function onEngagement(_e: Hooks["engagement.on_opened"]): Promise<void> {
  return sync(targets.list());
}

/** For tests: the pause between requests, and a promise of the work queued so far. */
export function setRequestGap(ms: number): void {
  gapMs = ms;
}
export function idle(): Promise<unknown> {
  return chain;
}

function background(list: Target[]): void {
  sync(list).catch((err) => log.error(`dnsdumpster: ${String(err)}`));
}

/**
 * Look up every enabled domain target not looked up yet in this engagement,
 * and forget the domains no longer targeted (so adding one back looks it up
 * again).
 */
async function sync(list: Target[]): Promise<void> {
  const wanted: string[] = [];
  for (const t of list) {
    const d = t.enabled ? domainOf(t.kind, t.value) : undefined;
    if (d && wanted.indexOf(d) < 0) wanted.push(d);
  }
  const todo = await enqueue(async () => {
    let done: string[];
    try {
      done = (await storage.engagement.get<string[]>(doneKey)) || [];
    } catch {
      return []; // no engagement open: nowhere to put what is found
    }
    const kept = done.filter((d) => wanted.indexOf(d) >= 0);
    if (kept.length !== done.length) await storage.engagement.set(doneKey, kept);
    return wanted.filter((d) => kept.indexOf(d) < 0 && !pending.has(d));
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
  const key = String(settings.get<string>("api_key") ?? "").trim();
  if (!key) {
    if (!warnedNoKey) log.warn("No DNSDumpster API key is set: add one in this plugin's settings to look targets up.");
    warnedNoKey = true;
    return;
  }
  const pages = Math.min(Math.max(Math.floor(Number(settings.get<number>("pages")) || 1), 1), 10);
  const opts = {
    cname: settings.get<boolean>("include_cname") !== false,
    mx: settings.get<boolean>("include_mx") === true,
    ns: settings.get<boolean>("include_ns") === true,
  };
  const found = emptyLookup();
  for (let page = 1; page <= pages; page++) {
    const reply = await request(domain, page, key);
    if (reply === undefined) {
      if (page === 1) return; // reported; tried again on the next change
      break; // keep what the earlier pages gave
    }
    if (readPage(reply, opts, found) === 0) break;
  }
  try {
    await apply(domain, found);
  } catch (err) {
    log.error(`${domain}: what DNSDumpster returned couldn't be added to the Explorer: ${String(err)}`);
  }
}

/** One page of a lookup, parsed; undefined (and logged) when it failed. */
async function request(domain: string, page: number, key: string): Promise<unknown> {
  const url = api + encodeURIComponent(domain) + (page > 1 ? `?page=${page}` : "");
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const wait = lastSend + gapMs - Date.now();
    if (wait > 0) await sleep(wait);
    lastSend = Date.now();
    let res;
    try {
      res = await http.send({ url, headers: { "X-API-Key": key, Accept: "application/json" } });
    } catch (err) {
      log.error(`${domain}: DNSDumpster couldn't be reached: ${String(err)}`);
      return undefined;
    }
    if (res.status === 429 && attempt < attempts) {
      lastSend = Date.now() + gapMs; // back off a little further than the limit
      continue;
    }
    if (res.status === 401 || res.status === 403) {
      log.error(`DNSDumpster refused the API key (HTTP ${res.status}); check it in this plugin's settings.`);
      return undefined;
    }
    if (!res.ok) {
      log.error(`${domain}: DNSDumpster answered HTTP ${res.status}: ${res.text().slice(0, 200)}`);
      return undefined;
    }
    const body = res.json();
    if (body === undefined) {
      log.error(`${domain}: DNSDumpster's answer wasn't JSON.`);
      return undefined;
    }
    return body;
  }
  log.error(`${domain}: DNSDumpster kept refusing requests as too frequent (HTTP 429).`);
  return undefined;
}

/** Put what a lookup found in the Explorer, and remember the domain as done. */
async function apply(domain: string, found: Lookup): Promise<void> {
  const from = attribution(domain, found);
  const withIPs = settings.get<boolean>("include_ips") !== false;
  let added = 0;
  for (const n of found.names.values()) {
    // The addresses go in as hosts of their own, and on the name as what
    // it resolves to; with addresses off, they are only noted.
    const res = await entities.addHost({
      host: n.name,
      addresses: withIPs ? n.ips : [],
      from,
      detail: `dnsdumpster:${n.types.join(",")}`,
    });
    if (res.created) added++;
    await note(res.entity.key, {
      "dnsdumpster.records": n.types.map((t) => t.toUpperCase()).join(", "),
      "dnsdumpster.ips": withIPs ? "" : n.ips.join(", "),
    });
  }
  if (withIPs) {
    for (const a of found.ips.values()) {
      const host = entities.get(a.ip);
      if (!host) continue;
      await note(host.key, {
        "dnsdumpster.asn": a.asn,
        "dnsdumpster.asn_name": a.asnName,
        "dnsdumpster.country": a.country,
        "dnsdumpster.ptr": a.ptr,
      });
    }
  }
  const done = (await storage.engagement.get<string[]>(doneKey)) || [];
  if (done.indexOf(domain) < 0) await storage.engagement.set(doneKey, [...done, domain]);
  log.info(`${domain}: DNSDumpster knows ${found.names.size} names and ${found.ips.size} addresses; ${added} names were new to the Explorer.`);
}

/**
 * The URL the discoveries are attributed to: the domain itself when a target
 * covers it, or else the first name found that one does. A host is listed
 * as Related only when what led to it is on a target.
 */
function attribution(domain: string, found: Lookup): string {
  for (const host of [domain, ...found.names.keys()]) {
    if (targets.match(`https://${host}/`)) return `https://${host}/`;
  }
  return `https://${domain}/`;
}

async function note(key: string, kv: Record<string, string>): Promise<void> {
  for (const name of Object.keys(kv)) {
    if (kv[name]) await entities.set(key, name, kv[name]);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
