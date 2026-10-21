// param-miner: discovers hidden request parameters and unkeyed inputs on
// one request the user picked.
//
// It is a right-click action and nothing else — no traffic or entity hooks,
// so it never runs on its own. The user chooses a request in the traffic
// list, picks "Param Miner", and the plugin guesses parameter names against
// that one request: common query/body/cookie names, and the proxy, routing
// and caching headers that matter behind a CDN or a load balancer — the
// inputs that change a response without being part of its cache key.
//
// How a guess is judged (src/detect.ts). First a baseline: the request with
// no guesses, sent a few times, to learn its status, its body length and
// how much both move on their own. Then names are sent in batches, each
// name carrying a value of its own. A name is a candidate when the response
// to its batch either reflects that name's value, or differs from the
// baseline by more than its noise; a reacting batch is bisected to the
// single name responsible. Every candidate is then re-sent on its own and
// only recorded if it reacts again — a guessed name that doesn't confirm is
// never reported.
//
// Being careful behind a CDN (src/probe.ts). Every probe carries a
// cache-buster — a query parameter unique to the run and the request — so a
// probe never shares a cache key with a real user. That is both a safeguard
// (a guessed header is tested for its effect without that effect being
// cached and served to anyone else) and a correctness measure (the answer
// comes from the origin, not a cached copy that would hide what the guess
// did). The plugin discovers these inputs; it does not attempt cache
// poisoning, which the finding's notes leave to the tester to confirm.
//
// It is active and can be noisy — hence an action the user triggers, on the
// host of the request they chose, bounded by a request cap and paced.

import { findings, http, log, settings, type ActionHandler, type Flow, type Location as FindingLocation } from "reproxy";
import { candidatesFor } from "./src/candidates";
import {
  baselineOf,
  canaryValue,
  howChanged,
  reflected,
  signalOf,
  type Baseline,
  type Candidate,
  type Location,
  type Signal,
} from "./src/detect";
import { buildProbe, canBody, type Add, type Base } from "./src/probe";

const LOCATIONS: Location[] = ["query", "header", "body", "cookie"];

interface Config {
  locations: Location[];
  extra: string[];
  maxRequests: number;
  batchSize: number;
  paceMs: number;
  maxFindings: number;
  baselineSamples: number;
  scanBytes: number;
  timeoutMs: number;
}

/** A confirmed parameter, and how it gave itself away. */
interface Hit {
  name: string;
  location: Location;
  method: "reflected" | "status" | "length";
  flowId: number;
}

/** A probe's result: its signal, and the text and flow to read it from. */
interface Result extends Signal {
  text: string;
  flowId: number;
}

// The run's canary prefix. Random, so a canary can't collide with page
// content; settable for tests so a scripted response can echo a known one.
let runToken = "";
export function setRunToken(t: string): void {
  runToken = t;
}

function newRun(): string {
  if (runToken) return runToken;
  let s = "";
  for (let i = 0; i < 6; i++) s += Math.floor(Math.random() * 36).toString(36);
  return s;
}

// Pacing is settable to zero for tests.
let paceOverride = -1;
export function setPace(ms: number): void {
  paceOverride = ms;
}

export const mine: ActionHandler = async ({ flow }) => {
  const cfg = config();
  const base = extractBase(flow);
  const run = newRun();
  const sender = new Sender(cfg);

  const bl = await baseline(sender, base, run, cfg);
  if (!bl) {
    return "Param Miner: couldn't get a response to measure against, so there is nothing to compare a guess to. Is the request still answerable?";
  }

  const hits: Hit[] = [];
  const found = new Set<string>(); // location\u0000name already recorded
  const skipped: string[] = [];
  const noisy: string[] = [];

  for (const loc of cfg.locations) {
    if (sender.done() || hits.length >= cfg.maxFindings) break;
    if (loc === "body" && !canBody(base)) {
      skipped.push("body (the request has no form or JSON body to add fields to)");
      continue;
    }
    if (loc === "cookie" && !hasCookies(base)) {
      // Cookies can still be added, but without any the app isn't cookie-driven here.
    }
    await mineLocation(sender, base, loc, bl, run, cfg, hits, found, noisy);
  }

  for (const h of hits) await record(flow, h, base);
  return summary(flow, base, sender, hits, skipped, noisy, bl);
};

// ---- Baseline -----------------------------------------------------------------

async function baseline(sender: Sender, base: Base, run: string, cfg: Config): Promise<Baseline | null> {
  const samples: Signal[] = [];
  for (let i = 0; i < cfg.baselineSamples; i++) {
    const r = await sender.send(run, (cb) => buildProbe(base, "query", [], cb));
    if (r) samples.push(signalOf(r.status, r.length));
  }
  if (samples.length < 2) return null;
  return baselineOf(samples);
}

// ---- Mining one location ------------------------------------------------------

async function mineLocation(
  sender: Sender,
  base: Base,
  loc: Location,
  bl: Baseline,
  run: string,
  cfg: Config,
  hits: Hit[],
  found: Set<string>,
  noisy: string[],
): Promise<void> {
  const names = candidatesFor(loc, cfg.extra, existingNames(base, loc));
  const cands: Candidate[] = names.map((name, i) => ({ name, location: loc, value: canaryValue(run, i) }));

  // Can this location be judged by how the response changes? If adding a
  // batch of names that cannot exist already moves the status, the app
  // reacts to any unknown input here, so behavioural detection would cry
  // wolf: fall back to reflection alone, and say so. If it only moves the
  // length (a page that echoes each parameter's existence, say), widen the
  // tolerance to absorb that rather than switch it off.
  let behavioural = bl.status !== -1 || bl.lengthStable;
  let pad = bl.pad;
  const junk: Add[] = [];
  for (let i = 0; i < cfg.batchSize; i++) junk.push({ name: `${run}zz${i}`, value: canaryValue(run, 1_000_000 + i) });
  const ctl = await sender.send(run, (cb) => buildProbe(base, loc, junk, cb));
  if (ctl) {
    const padded = { ...bl, pad };
    if (behavioural && howChanged(padded, ctl) === "status") {
      behavioural = false;
      noisy.push(`${loc} (the app changes its status on any unknown input, so only reflected names are reported there)`);
    } else if (howChanged(padded, ctl) === "length") {
      const over = Math.max(ctl.length - bl.maxLength, bl.minLength - ctl.length, 0);
      pad = Math.max(pad, over + pad);
    }
  }

  for (let i = 0; i < cands.length; i += cfg.batchSize) {
    if (sender.done() || hits.length >= cfg.maxFindings) return;
    const batch = cands.slice(i, i + cfg.batchSize);
    const r = await sender.send(run, (cb) => buildProbe(base, loc, adds(batch), cb));
    if (!r) continue;

    for (const c of reflected(r.text, run, batch)) {
      await consider(sender, base, bl, pad, run, c, "reflected", cfg, hits, found);
      if (hits.length >= cfg.maxFindings) return;
    }
    if (behavioural) {
      const how = howChanged({ ...bl, pad }, r);
      if (how) {
        for (const c of await bisect(sender, base, loc, batch, bl, pad, run)) {
          await consider(sender, base, bl, pad, run, c, how, cfg, hits, found);
          if (hits.length >= cfg.maxFindings) return;
        }
      }
    }
  }
}

/**
 * bisect narrows a reacting batch to the single names responsible, by
 * halving and re-sending each half that still reacts. It stops when the
 * request budget runs out rather than guess.
 */
async function bisect(
  sender: Sender,
  base: Base,
  loc: Location,
  cands: Candidate[],
  bl: Baseline,
  pad: number,
  run: string,
): Promise<Candidate[]> {
  if (cands.length <= 1) return cands;
  const mid = Math.floor(cands.length / 2);
  const out: Candidate[] = [];
  for (const half of [cands.slice(0, mid), cands.slice(mid)]) {
    if (half.length === 0 || sender.done()) continue;
    const r = await sender.send(run, (cb) => buildProbe(base, loc, adds(half), cb));
    if (r && howChanged({ ...bl, pad }, r)) {
      out.push(...(await bisect(sender, base, loc, half, bl, pad, run)));
    }
  }
  return out;
}

/**
 * consider confirms one candidate on its own and records it only if it
 * reacts again. A guessed name that doesn't reproduce is not reported.
 */
async function consider(
  sender: Sender,
  base: Base,
  bl: Baseline,
  pad: number,
  run: string,
  cand: Candidate,
  method: "reflected" | "status" | "length",
  cfg: Config,
  hits: Hit[],
  found: Set<string>,
): Promise<void> {
  const key = `${cand.location}\u0000${cand.name.toLowerCase()}`;
  if (found.has(key) || hits.length >= cfg.maxFindings) return;
  const r = await sender.send(run, (cb) => buildProbe(base, cand.location, [{ name: cand.name, value: cand.value }], cb));
  if (!r) return;
  const ok = method === "reflected" ? reflected(r.text, run, [cand]).length > 0 : howChanged({ ...bl, pad }, r) === method;
  if (!ok) return;
  found.add(key);
  hits.push({ name: cand.name, location: cand.location, method, flowId: r.flowId });
}

// ---- Sending ------------------------------------------------------------------

/** Sender sends probes one at a time, paced, counting them against the cap. */
class Sender {
  used = 0;
  private seq = 0;
  constructor(private cfg: Config) {}

  done(): boolean {
    return this.used >= this.cfg.maxRequests;
  }

  async send(run: string, make: (cb: Add) => ReturnType<typeof buildProbe>): Promise<Result | undefined> {
    if (this.done()) return undefined;
    const pace = paceOverride >= 0 ? paceOverride : this.cfg.paceMs;
    if (pace > 0 && this.used > 0) await sleep(pace);
    this.used++;
    const cb: Add = { name: `cb_${run}`, value: `${run}${this.seq++}` };
    const probe = make(cb);
    let res;
    try {
      res = await http.send(probe, { record: true, timeoutMs: this.cfg.timeoutMs });
    } catch (e) {
      log.debug(`probe failed: ${String(e)}`);
      return undefined;
    }
    const binary = res.isBinary();
    const full = binary ? "" : res.text();
    const text = full.length > this.cfg.scanBytes ? full.slice(0, this.cfg.scanBytes) : full;
    return { status: res.status, length: binary ? res.size : full.length, text, flowId: res.flowId };
  }
}

// ---- Recording ----------------------------------------------------------------

async function record(flow: Flow, h: Hit, base: Base): Promise<void> {
  const host = flow.host.toLowerCase();
  const where = place(h.location);
  const how =
    h.method === "reflected"
      ? `its value was reflected in the response`
      : h.method === "status"
        ? `sending it changed the response status`
        : `sending it changed the response length`;

  let notes =
    `A hidden ${where} named "${h.name}" is accepted by ${flow.method} ${pathOf(base.url)} on ${host}: ` +
    `it isn't in the request as the app sends it, but ${how}, and re-sending it on its own reproduced that. ` +
    `A parameter the client never sets is one the developers didn't expect a tester to find, so it is worth ` +
    `reading for behaviour that the normal interface doesn't reach — debug output, access-control toggles, ` +
    `or input that is trusted because it "can't" be supplied.`;

  if (h.location === "header") {
    notes +=
      `\n\nThis is a request header that changes the response. Behind a CDN or a load balancer that is the ` +
      `shape of an unkeyed input: if it alters a response that is then cached under a key that doesn't ` +
      `include it, it is a web-cache-poisoning lead worth confirming by hand. Each probe here carried a ` +
      `cache-buster, so nothing was poisoned in finding it.`;
  }
  if (h.method === "reflected") {
    notes += `\n\nReflected input is also worth checking for XSS and for open redirects, depending on where in the response it lands.`;
  }

  await findings.record({
    value: `${h.name} (${where}, ${host})`,
    types: ["hidden-param"],
    notes,
    fields: {
      host,
      name: h.name,
      location: h.location,
      detection: h.method,
      request: `${flow.method} ${pathOf(base.url)}`,
    },
    flowId: h.flowId || flow.id,
    location: "response_body" as FindingLocation,
    detail: h.name,
  });
}

function summary(
  flow: Flow,
  base: Base,
  sender: Sender,
  hits: Hit[],
  skipped: string[],
  noisy: string[],
  bl: Baseline,
): string {
  const head = `Param Miner on ${flow.method} ${pathOf(base.url)}: ${sender.used} requests sent`;
  const lines: string[] = [];
  if (hits.length === 0) {
    lines.push("no hidden parameters confirmed.");
  } else {
    lines.push(`${hits.length} hidden parameter${hits.length === 1 ? "" : "s"} found:`);
    for (const h of hits) lines.push(`  • ${h.name} (${place(h.location)}, ${h.method})`);
  }
  if (bl.status === -1 && !bl.lengthStable) {
    lines.push("The response varied between identical requests, so only reflected names could be judged.");
  }
  for (const n of noisy) lines.push(`Note: ${n}.`);
  for (const s of skipped) lines.push(`Skipped ${s}.`);
  if (sender.done()) lines.push(`Stopped at the request cap (${sender.used}); raise "Most requests to send" to go further.`);
  return `${head}. ${lines.join(" ")}`;
}

// ---- Odds and ends ------------------------------------------------------------

function config(): Config {
  const raw = (settings.get<string[]>("locations") || ["query", "header"]).map((s) => String(s).toLowerCase());
  const locations = LOCATIONS.filter((l) => raw.indexOf(l) >= 0);
  return {
    locations: locations.length > 0 ? locations : ["query", "header"],
    extra: settings.get<string[]>("wordlist") || [],
    maxRequests: clamp(settings.get<number>("max_requests"), 300, 8, 20000),
    batchSize: clamp(settings.get<number>("batch_size"), 24, 1, 128),
    paceMs: clamp(settings.get<number>("pace_ms"), 120, 0, 10000),
    maxFindings: clamp(settings.get<number>("max_findings"), 50, 1, 1000),
    baselineSamples: clamp(settings.get<number>("baseline_samples"), 3, 2, 10),
    scanBytes: clamp(settings.get<number>("max_scan_kb"), 1024, 16, 16384) * 1024,
    timeoutMs: 15000,
  };
}

function extractBase(flow: Flow): Base {
  const headers: [string, string][] = flow.request.headers().map((h) => [h.name, h.value]);
  const body = flow.request.empty || flow.request.isBinary() ? "" : flow.request.text();
  return { url: flow.url, method: flow.method, headers, body, contentType: flow.request.contentType() };
}

/** adds turns candidates into the name/value pairs a probe takes. */
function adds(cands: Candidate[]): Add[] {
  return cands.map((c) => ({ name: c.name, value: c.value }));
}

/** existingNames lists the names the request already uses at a location, so
 *  they aren't guessed: a parameter already present isn't a hidden one. */
function existingNames(base: Base, loc: Location): string[] {
  switch (loc) {
    case "query":
      return pairNames(queryOf(base.url));
    case "header":
      return base.headers.map(([n]) => n);
    case "cookie": {
      const cookie = base.headers.find(([n]) => n.toLowerCase() === "cookie");
      return cookie ? cookie[1].split(";").map((p) => p.split("=")[0].trim()).filter(Boolean) : [];
    }
    case "body":
      return base.contentType.indexOf("json") >= 0 ? [] : pairNames(base.body);
  }
}

function hasCookies(base: Base): boolean {
  return base.headers.some(([n]) => n.toLowerCase() === "cookie");
}

function pairNames(s: string): string[] {
  const out: string[] = [];
  for (const part of s.split("&")) {
    const eq = part.indexOf("=");
    const name = (eq < 0 ? part : part.slice(0, eq)).trim();
    if (name) out.push(decodeURIComponent(name));
  }
  return out;
}

function queryOf(url: string): string {
  const q = url.indexOf("?");
  if (q < 0) return "";
  const h = url.indexOf("#", q);
  return h < 0 ? url.slice(q + 1) : url.slice(q + 1, h);
}

function pathOf(url: string): string {
  const s = url.indexOf("://");
  const rest = s < 0 ? url : url.slice(s + 3);
  const slash = rest.indexOf("/");
  const path = slash < 0 ? "/" : rest.slice(slash);
  const q = path.indexOf("?");
  return q < 0 ? path : path.slice(0, q);
}

function place(loc: Location): string {
  switch (loc) {
    case "query":
      return "query parameter";
    case "header":
      return "header";
    case "cookie":
      return "cookie";
    case "body":
      return "body parameter";
  }
}

function clamp(v: unknown, dflt: number, min: number, max: number): number {
  const n = Math.floor(Number(v));
  return Math.min(Math.max(Number.isFinite(n) && v !== undefined && v !== null ? n : dflt, min), max);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
