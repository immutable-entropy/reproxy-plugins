// 403-bypasser: tries the well-known tricks for reaching a 401/403-protected
// endpoint, and records each one that works as a finding.
//
// It is a right-click action and nothing else — no traffic or entity hooks, so
// it never runs on its own. The tester picks a request that comes back blocked,
// chooses "403 Bypasser", and the plugin re-sends that request many ways:
//
//   • path mutations — the payloads the original 403-bypasser uses, inserted
//     around the path, plus the usual structural tricks (trailing slash, //,
//     /..;/, case changes, suffixes);
//   • header injection — the IP/forwarding headers (X-Forwarded-For: 127.0.0.1
//     and friends) added to the request;
//   • URL-override headers — the blocked path carried in X-Original-URL /
//     X-Rewrite-URL against a permitted base path;
//   • method swaps — POST, HEAD, OPTIONS in place of the original method;
//   • an HTTP/1.0 downgrade — the same request on the wire as HTTP/1.0.
//
// How a bypass is judged (src/detect.ts). First a baseline: the unchanged
// request, sent a few times, which must come back blocked (401/403). A variant
// counts only if it is no longer blocked, reaches a content-serving status, and
// its body differs from the block page — and, for an override, from the base
// path too. Every candidate is then re-sent and recorded only if it reproduces,
// so a one-off fluke is never reported.
//
// It is active and can be noisy — hence an action the tester triggers, on the
// host of the request they chose, bounded by a request cap and paced. Every
// probe carries a cache-buster so an odd request never shares a cache key with
// a real user.

import { findings, http, log, settings, type ActionHandler, type Flow, type Location as FindingLocation } from "reproxy";
import {
  blockedBaselineOf,
  isBlocked,
  reacted,
  signalOf,
  type Baseline,
  type Signal,
  type Why,
} from "./src/detect";
import { buildProbe, type Add, type Base } from "./src/probe";
import {
  downgradeVariant,
  headerVariants,
  methodVariants,
  overrideBaseUrl,
  overrideVariants,
  pathOf,
  pathVariants,
  type Technique,
  type Variant,
} from "./src/variants";
import PATH_PAYLOADS from "./path-payloads.json";
import HEADER_PAYLOADS from "./header-payloads.json";

const TECHNIQUES: Technique[] = ["path", "header", "override", "method", "downgrade"];

interface Config {
  techniques: Technique[];
  pathPayloads: string[];
  injectHeaders: string[];
  overrideHeaders: string[];
  overrideBase: string;
  methods: string[];
  downgradeStrip: boolean;
  blockedStatus: number[];
  includeRedirects: boolean;
  requireBlock: boolean;
  cacheBuster: boolean;
  maxRequests: number;
  paceMs: number;
  maxFindings: number;
  baselineSamples: number;
  scanBytes: number;
  timeoutMs: number;
}

/** A confirmed bypass. */
interface Hit {
  technique: Technique;
  detail: string;
  why: Why;
  status: number;
  length: number;
  flowId: number;
}

// The run's cache-buster prefix. Random, so it can't collide with real
// traffic; settable for tests so a probe's URL is predictable.
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

export const bypass: ActionHandler = async ({ flow }) => {
  const cfg = config();
  const base = extractBase(flow);
  const run = newRun();
  const sender = new Sender(cfg, run);
  const target = `${flow.method} ${pathOf(base.url)}`;

  const bl = await baseline(sender, base, cfg);
  if (!bl) {
    return `403 Bypasser: couldn't get a response to measure against for ${target}. Is the request still answerable?`;
  }
  if (cfg.requireBlock && (bl.status === -1 || !isBlocked(bl.status, cfg.blockedStatus))) {
    const seen = bl.status === -1 ? "an unstable status" : `${bl.status}`;
    return `403 Bypasser: ${target} returns ${seen}, not ${cfg.blockedStatus.join("/")} — nothing to bypass. Turn off "Require a blocked baseline" to test it anyway.`;
  }

  // The override technique needs the permitted base path's own response to
  // compare against, so an override that just echoes it isn't mistaken for a hit.
  let control: Signal | undefined;
  if (cfg.techniques.indexOf("override") >= 0) {
    const url = overrideBaseUrl(base.url, cfg.overrideBase);
    const r = await sender.send((cb) => buildProbe(base, { url }, cb));
    if (r) control = r;
  }

  const variants = buildVariants(base, flow, cfg);

  const hits: Hit[] = [];
  const seen = new Set<string>(); // technique\u0000detail already recorded
  for (const v of variants) {
    if (sender.done() || hits.length >= cfg.maxFindings) break;
    const key = `${v.technique}\u0000${v.detail}`;
    if (seen.has(key)) continue;

    const r = await sender.send((cb) => buildProbe(base, v.mutation, cb));
    if (!r) continue;
    const judge = { blocked: cfg.blockedStatus, includeRedirects: cfg.includeRedirects, control: isOverride(v) ? control : undefined };
    if (!reacted(bl, r, judge)) continue;

    // Confirm on its own before recording: a one-off fluke is not a finding.
    const r2 = await sender.send((cb) => buildProbe(base, v.mutation, cb));
    if (!r2) continue;
    const why = reacted(bl, r2, judge);
    if (!why) continue;

    seen.add(key);
    hits.push({ technique: v.technique, detail: v.detail, why, status: r2.status, length: r2.length, flowId: r2.flowId });
  }

  for (const h of hits) await record(flow, base, bl, h);
  return summary(target, sender, hits, bl, cfg);
};

// ---- Baseline -----------------------------------------------------------------

async function baseline(sender: Sender, base: Base, cfg: Config): Promise<Baseline | null> {
  const samples: Signal[] = [];
  for (let i = 0; i < cfg.baselineSamples; i++) {
    const r = await sender.send((cb) => buildProbe(base, { url: base.url }, cb));
    if (r) samples.push(r);
  }
  if (samples.length < 2) return null;
  return blockedBaselineOf(samples);
}

// ---- Variant generation -------------------------------------------------------

function buildVariants(base: Base, flow: Flow, cfg: Config): Variant[] {
  const out: Variant[] = [];
  for (const t of cfg.techniques) {
    switch (t) {
      case "path":
        out.push(...pathVariants(base.url, cfg.pathPayloads));
        break;
      case "header":
        out.push(...headerVariants(base.url, cfg.injectHeaders));
        break;
      case "override":
        out.push(...overrideVariants(base.url, cfg.overrideBase, cfg.overrideHeaders));
        break;
      case "method":
        out.push(...methodVariants(base.url, flow.method, cfg.methods));
        break;
      case "downgrade":
        out.push(downgradeVariant(base.url, flow.method, cfg.downgradeStrip));
        break;
    }
  }
  return out;
}

function isOverride(v: Variant): boolean {
  return v.technique === "override";
}

// ---- Sending ------------------------------------------------------------------

/** Sender sends probes one at a time, paced, counting them against the cap. */
class Sender {
  used = 0;
  private seq = 0;
  constructor(
    private cfg: Config,
    private run: string,
  ) {}

  done(): boolean {
    return this.used >= this.cfg.maxRequests;
  }

  async send(make: (cb?: Add) => ReturnType<typeof buildProbe>): Promise<(Signal & { flowId: number }) | undefined> {
    if (this.done()) return undefined;
    const pace = paceOverride >= 0 ? paceOverride : this.cfg.paceMs;
    if (pace > 0 && this.used > 0) await sleep(pace);
    this.used++;
    const cb = this.cfg.cacheBuster ? { name: `cb_${this.run}`, value: `${this.seq++}` } : undefined;
    let res;
    try {
      res = await http.send(make(cb), { record: true, timeoutMs: this.cfg.timeoutMs });
    } catch (e) {
      log.debug(`probe failed: ${String(e)}`);
      return undefined;
    }
    const binary = res.isBinary();
    const full = binary ? "" : res.text();
    const body = full.length > this.cfg.scanBytes ? full.slice(0, this.cfg.scanBytes) : full;
    const length = binary ? res.size : full.length;
    const sig = signalOf(res.status, length, body);
    return { ...sig, flowId: res.flowId };
  }
}

// ---- Recording ----------------------------------------------------------------

async function record(flow: Flow, base: Base, bl: Baseline, h: Hit): Promise<void> {
  const host = flow.host.toLowerCase();
  const path = pathOf(base.url);
  const baselineStatus = bl.status === -1 ? "a blocked status" : `${bl.status}`;

  let notes =
    `${flow.method} ${path} on ${host} comes back ${baselineStatus}, but the ${techniqueName(h.technique)} ` +
    `technique reached it: ${h.detail} returned ${h.status} with a different response (${diffPhrase(h.why)}), ` +
    `and re-sending it reproduced that. The access control can be bypassed, so whatever it was protecting is reachable. ` +
    remediation(h.technique);

  await findings.record({
    value: `${host}${path} via ${h.technique}: ${h.detail}`,
    types: ["bypass"],
    notes,
    fields: {
      host,
      request: `${flow.method} ${path}`,
      technique: h.technique,
      detail: h.detail,
      baseline: baselineStatus,
      result: `${h.status}`,
      length: `${h.length}`,
    },
    flowId: h.flowId || flow.id,
    location: "response_header" as FindingLocation,
    detail: `${h.technique}: ${h.detail}`,
  });
}

function techniqueName(t: Technique): string {
  switch (t) {
    case "path":
      return "path-mutation";
    case "header":
      return "header-injection";
    case "override":
      return "URL-override header";
    case "method":
      return "method-swap";
    case "downgrade":
      return "HTTP/1.0 downgrade";
  }
}

function diffPhrase(why: Why): string {
  switch (why) {
    case "length":
      return "its length is outside the block page's";
    case "body":
      return "its body differs from the block page's";
    case "status":
      return "it is no longer the block page";
    default:
      return "it differs from the block page";
  }
}

function remediation(t: Technique): string {
  switch (t) {
    case "path":
      return (
        `Decide access on the path the application actually resolves: normalise and decode it (collapse ` +
        `. and .. segments, duplicate and trailing slashes, and percent-encoding, including matrix ";" parameters) ` +
        `before the authorization check, and make the proxy's ACL and the application agree on that normalised form.`
      );
    case "header":
      return (
        `Don't let a client-supplied header stand in for the real peer address or authorise a request. Strip or ignore ` +
        `X-Forwarded-*, X-Real-IP, X-Custom-IP-Authorization and the like at the edge unless they come from a trusted ` +
        `proxy, and take the client IP from the connection, not from a header.`
      );
    case "override":
      return (
        `Don't let X-Original-URL, X-Rewrite-URL or similar headers re-point the request past the ACL. Ignore them ` +
        `unless a trusted front end sets them, and apply authorization to the path actually served.`
      );
    case "method":
      return (
        `Apply the access control to every method, not just the one the UI uses. A rule that only blocks GET (or only ` +
        `the listed methods) leaves the resource reachable by another method.`
      );
    case "downgrade":
      return (
        `Apply the same access control regardless of HTTP version. If an older protocol path skips the check (or a ` +
        `front end only filters HTTP/1.1/2), close that path or bring it under the same policy.`
      );
  }
}

function summary(target: string, sender: Sender, hits: Hit[], bl: Baseline, cfg: Config): string {
  const head = `403 Bypasser on ${target} (baseline ${bl.status === -1 ? "unstable" : bl.status}): ${sender.used} requests sent`;
  const lines: string[] = [];
  if (hits.length === 0) {
    lines.push("no bypass found.");
  } else {
    lines.push(`${hits.length} bypass${hits.length === 1 ? "" : "es"} confirmed:`);
    for (const h of hits) lines.push(`  • ${techniqueName(h.technique)} — ${h.detail} → ${h.status}`);
  }
  if (sender.done()) lines.push(`Stopped at the request cap (${sender.used}); raise "Most requests to send" to go further.`);
  return `${head}. ${lines.join(" ")}`;
}

// ---- Odds and ends ------------------------------------------------------------

function config(): Config {
  const rawTech = (settings.get<string[]>("techniques") || TECHNIQUES).map((s) => String(s).toLowerCase());
  const techniques = TECHNIQUES.filter((t) => rawTech.indexOf(t) >= 0);
  return {
    techniques: techniques.length > 0 ? techniques : TECHNIQUES,
    pathPayloads: merge(PATH_PAYLOADS as string[], settings.get<string[]>("path_payloads")),
    injectHeaders: merge(HEADER_PAYLOADS as string[], settings.get<string[]>("inject_headers")),
    overrideHeaders: list(settings.get<string[]>("override_headers"), ["X-Original-URL", "X-Rewrite-URL", "X-Original-Url", "X-Override-URL", "X-Rewrite-Url"]),
    overrideBase: str(settings.get<string>("override_base"), "/"),
    methods: list(settings.get<string[]>("methods"), ["POST", "HEAD", "OPTIONS"]),
    downgradeStrip: settings.get<boolean>("downgrade_strip_headers") === true,
    blockedStatus: numbers(settings.get<unknown[]>("blocked_status"), [401, 403]),
    includeRedirects: settings.get<boolean>("include_redirects") === true,
    requireBlock: settings.get<boolean>("require_block") !== false,
    cacheBuster: settings.get<boolean>("cache_buster") !== false,
    maxRequests: clamp(settings.get<number>("max_requests"), 400, 8, 20000),
    paceMs: clamp(settings.get<number>("pace_ms"), 120, 0, 10000),
    maxFindings: clamp(settings.get<number>("max_findings"), 50, 1, 1000),
    baselineSamples: clamp(settings.get<number>("baseline_samples"), 3, 2, 10),
    scanBytes: clamp(settings.get<number>("max_scan_kb"), 512, 16, 16384) * 1024,
    timeoutMs: 15000,
  };
}

function extractBase(flow: Flow): Base {
  const headers: [string, string][] = flow.request.headers().map((h) => [h.name, h.value]);
  const body = flow.request.empty || flow.request.isBinary() ? "" : flow.request.text();
  return { url: flow.url, method: flow.method, headers, body, contentType: flow.request.contentType() };
}

/** merge appends the user's extra entries to a bundled list, de-duplicated
 *  case-insensitively and keeping the bundled order first. */
function merge(bundled: string[], extra: string[] | undefined): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of [...bundled, ...(extra || [])]) {
    const v = String(raw).trim();
    if (!v) continue;
    const key = v.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(v);
  }
  return out;
}

/** list returns the user's list if they set a non-empty one, else the default. */
function list(v: string[] | undefined, dflt: string[]): string[] {
  const out = (v || []).map((s) => String(s).trim()).filter(Boolean);
  return out.length > 0 ? out : dflt;
}

function numbers(v: unknown[] | undefined, dflt: number[]): number[] {
  const out: number[] = [];
  for (const raw of v || []) {
    const n = Math.floor(Number(raw));
    if (Number.isFinite(n) && n >= 100 && n <= 599) out.push(n);
  }
  return out.length > 0 ? out : dflt;
}

function str(v: string | undefined, dflt: string): string {
  const s = (v === undefined || v === null ? "" : String(v)).trim();
  return s === "" ? dflt : s;
}

function clamp(v: unknown, dflt: number, min: number, max: number): number {
  const n = Math.floor(Number(v));
  return Math.min(Math.max(Number.isFinite(n) && v !== undefined && v !== null ? n : dflt, min), max);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
