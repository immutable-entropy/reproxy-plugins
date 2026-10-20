// laravel: reports the misconfigurations a Laravel application gives away
// in its own traffic.
//
// Four of them account for most of what goes wrong with a Laravel
// deployment, and all four are visible from the outside:
//
//   - debug mode left on, so an exception is answered with Ignition's or
//     Whoops' page, or with a JSON reply carrying the stack trace — the
//     source paths, the framework and PHP versions, the SQL that failed
//     and, where the handler prints the process environment, APP_KEY and
//     the database password (src/debug.ts);
//   - development tooling left routed: Telescope, Horizon, Pulse, the
//     Debugbar, Clockwork, Ignition's own routes, a log viewer — each
//     installed to show everything the application does, and doing that
//     for anyone who reaches it (src/exposure.ts);
//   - a document root pointed at the project directory instead of
//     public/, which serves .env, composer.json, storage/ and vendor/;
//   - session cookies without Secure, HttpOnly or SameSite
//     (src/cookies.ts).
//
// It reads traffic that has already passed, so it never slows the proxy
// down and the site learns nothing from it. Each target's match filter
// keeps the work small: the header check is a string read of the head, the
// body is only read for pages that could be an error page, and the
// exposures are matched by path in Go before anything reaches this code.
//
// Nothing is reported for a host until something has shown it to run
// Laravel (src/detect.ts). One strong signal is enough — an encrypted
// Laravel cookie, a package's route, the framework's own path in a page —
// and otherwise two weaker ones; the evidence goes in the finding, so the
// tester can judge it rather than take the label on trust. An exposure
// confirmed from its content (Telescope's dashboard, a real .env) is proof
// in itself.
//
// Everything above is passive. If the user turns the active check on, a
// host shown to run Laravel is asked for a short list of paths — .env,
// telescope, horizon and the rest — and only on hosts the targets cover.
//
// That check runs once per host and never again. The engagement keeps a
// record of every host this plugin has dealt with: why it was taken for
// Laravel, when it was checked, and what the check found. The record is
// written before the first request goes out, so a check interrupted
// half-way still counts as done, and it is read back on load, so a reload,
// a restart or a second visit to the site sends nothing more. The same
// record stops a known host being worked out from scratch again: it goes
// straight back on the list of Laravel hosts, so the passive checks carry
// on, without re-recording the site or queueing another round of requests.
// What was found is also noted on the origin in the Entity Explorer
// (laravel / laravel-checked), where the user and other plugins can see it.

import {
  entities,
  findings,
  http,
  log,
  settings,
  storage,
  targets,
  type Flow,
  type Hooks,
  type Location,
  type Response,
} from "reproxy";
import { describe, issues, kindOf, parseSetCookie, setCookies } from "./src/cookies";
import { appKeyIn, readHtmlError, readJsonError, type DebugError } from "./src/debug";
import { fromCookie, fromHeaders, fromHtml, fromPath, verdict, type Signal } from "./src/detect";
import { exposureFor, type Exposure } from "./src/exposure";

/** Where something was seen: a flow of the browser's, or one of our own. */
interface At {
  host: string;
  scheme: string;
  method: string;
  path: string;
  status: number;
  flowId: number;
  origin: string;
}

/**
 * What the engagement remembers about a host this plugin has dealt with,
 * kept under one key in storage.engagement so it survives a reload, a
 * restart and a second visit to the same site.
 */
interface Known {
  /** Why the host was taken for Laravel. */
  evidence: string;
  /** When it was first recognised, and when the active check ran (0: never). */
  seen: number;
  checked: number;
  /** The origin the check ran against, and how many paths it asked for. */
  origin: string;
  asked: number;
  /** What it found: exposure ids, and the kind of any debug page. */
  found: string[];
}

const knownKey = "laravel_hosts";

/** The engagement's record, read once and written back as it changes. */
let known: Record<string, Known> | undefined;

/** At most this many hosts are remembered; the oldest are dropped. */
const maxKnown = 500;

// Session state. Findings merge on their value, so nothing is lost by
// forgetting this between runs: it only keeps the plugin from doing the
// same work twice while it runs.
const recorded = new Set<string>(); // findings already recorded this run
const laravelHosts = new Set<string>(); // hosts shown to run Laravel
const checkedHosts = new Set<string>(); // hosts the active check has taken
const weakSignals: Record<string, string[]> = {}; // host → weak evidence so far
let chain: Promise<unknown> = Promise.resolve();
let warned = false;

/** A pause between active requests, so a check never bursts at a host. */
let gapMs = 200;
let lastSend = 0;

export function load(_e?: Hooks["plugin.on_load"]): void {
  recorded.clear();
  laravelHosts.clear();
  checkedHosts.clear();
  known = undefined;
  for (const k of Object.keys(weakSignals)) delete weakSignals[k];
  chain = Promise.resolve();
  warned = false;
}

/**
 * onEngagement starts again when another engagement is opened: what a host
 * was asked belongs to the engagement it was asked in, so the remembered
 * record has to be read again from the engagement now open.
 */
export function onEngagement(_e?: Hooks["engagement.on_opened"]): void {
  load();
}

/** For tests: the pause between active requests, and the work queued so far. */
export function setRequestGap(ms: number): void {
  gapMs = ms;
}
export function idle(): Promise<unknown> {
  return chain;
}

// ---- The hooks ----------------------------------------------------------------

/**
 * onHeaders reads the head of every in-scope response: the cookies Laravel
 * set, and the headers its Debugbar adds. A head is small, so this costs a
 * handful of string operations per response and never touches the body.
 */
export async function onHeaders({ flow }: Hooks["traffic.on_response_received"]): Promise<void> {
  if (flow.response.empty) return;
  const headers = flow.response.headers();
  const cookies = parseSetCookie(setCookies(headers));
  const signals = fromHeaders(headers);
  for (const c of cookies) {
    const s = fromCookie(c, kindOf(c));
    if (s) signals.push(s);
  }
  const where = at(flow);
  await note(where, signals);
  probe(where);

  if (settings.get<boolean>("check_cookies") === false) return;
  const host = where.host;
  if (!laravelHosts.has(host)) return;
  for (const c of cookies) {
    const kind = kindOf(c);
    if (kind === "") continue;
    for (const issue of issues(c, kind, flow.scheme === "https")) {
      await record(`cookie:${host}:${c.name}:${issue.id}`, {
        value: `${c.name} ${issue.short} (${host})`,
        types: ["laravel-config"],
        notes: `${c.name} is ${describe(kind)}. ${issue.note}\n\nFix: ${issue.fix}`,
        fields: { host, cookie: c.name, attributes: attributesOf(c.secure, c.httpOnly, c.sameSite) },
        flowId: flow.id,
        location: "response_header",
        detail: "Set-Cookie",
      });
    }
  }
}

/**
 * onBody reads a response that could be an error page: any HTML the app
 * served, and the HTML, JSON or text of a 4xx or 5xx. Those are the only
 * two ways a Laravel application admits to having debug mode on.
 */
export async function onBody({ flow }: Hooks["traffic.on_response_received"]): Promise<void> {
  if (flow.response.empty || flow.response.size > maxBody()) return;
  const type = flow.response.contentType();
  const signals = fromPath(flow.path);
  let err: DebugError | undefined;

  if (type.indexOf("json") >= 0) {
    err = readJsonError(flow.response.json());
  } else if (!flow.response.isBinary()) {
    const body = flow.response.text();
    const lower = body.toLowerCase();
    for (const s of fromHtml(lower)) signals.push(s);
    err = readHtmlError(body, lower);
  }
  if (err) signals.push({ why: err.evidence, strong: err.laravel || err.kind === "ignition" });

  const where = at(flow);
  await note(where, signals);
  probe(where);
  if (err) await recordDebug(where, err);
}

/**
 * onExposedPath handles a 2xx on one of the paths a Laravel deployment
 * should not be serving. The path is matched in Go; what came back decides
 * whether it is really there, since a single-page app answers 200 with its
 * own shell for any route at all.
 */
export async function onExposedPath({ flow }: Hooks["traffic.on_response_received"]): Promise<void> {
  if (flow.response.empty) return;
  const type = flow.response.contentType();
  const body = flow.response.isBinary() || flow.response.size > maxBody() ? "" : flow.response.text();
  const exposure = exposureFor(flow.path, type, body);
  if (!exposure) return;
  const where = at(flow);
  await handleExposure(where, exposure, body);
  probe(where);
}

// ---- Recording ----------------------------------------------------------------

/**
 * note weighs what a response said about the stack, and records the site
 * the first time the evidence adds up to Laravel. Weak signals are kept per
 * host, so two of them seen in different responses still count.
 */
async function note(where: At, signals: Signal[]): Promise<void> {
  if (laravelHosts.has(where.host)) return;

  // A host this engagement has already dealt with is not worked out again:
  // the site finding is in the engagement already, and re-recognising it
  // would only queue the same active check a second time. The passive
  // checks still need to know it is Laravel, so it goes back in the set.
  const before = await remembered(where.host);
  if (before) {
    laravelHosts.add(where.host);
    if (before.checked) checkedHosts.add(where.host);
    return;
  }
  if (signals.length === 0) return;

  const all = signals.slice();
  for (const why of weakSignals[where.host] || []) all.push({ why, strong: false });

  const v = verdict(all);
  if (!v.laravel) {
    const kept = weakSignals[where.host] || (weakSignals[where.host] = []);
    for (const s of signals) {
      if (!s.strong && kept.indexOf(s.why) < 0 && kept.length < 8) kept.push(s.why);
    }
    return;
  }

  laravelHosts.add(where.host);
  delete weakSignals[where.host];
  await remember(where.host, { evidence: v.why, seen: Date.now(), checked: 0, origin: where.origin, asked: 0, found: [] });
  await mark(where.origin, "laravel", v.certain ? `yes — ${v.why}` : `probably — ${v.why}`);
  await record(`site:${where.host}`, {
    value: siteValue(where.host),
    types: ["laravel"],
    notes:
      `${where.host} runs Laravel — ${v.why}.` +
      (v.certain ? "" : " Each of those is something other stacks do as well, so this is probable rather than certain.") +
      ` What follows about this host's debug mode, exposed tooling and session cookies was read from ` +
      `traffic that had already passed; nothing was requested for it.`,
    fields: { host: where.host, evidence: v.why },
    flowId: where.flowId || undefined,
  });
}

/** recordVersion merges a framework version into the site's finding. */
async function recordVersion(host: string, version: string, from: string, flowId: number): Promise<void> {
  if (!version) return;
  await record(`version:${host}:${version}`, {
    value: siteValue(host),
    types: ["laravel"],
    notes:
      `Laravel ${version}, from ${from}. Compare it with the current release: Laravel's security fixes ` +
      `go into the latest patch of each supported branch, and a branch past its support window gets none at all.`,
    fields: { host, laravel_version: version },
    flowId: flowId || undefined,
  });
}

async function recordDebug(where: At, e: DebugError): Promise<void> {
  if (!laravelHosts.has(where.host)) return;

  const fields: Record<string, string> = { host: where.host, error_page: e.kind };
  let notes = `Debug mode is on for ${where.host}: a ${where.status} answer carried ${e.evidence}.`;
  if (e.message) notes += ` The page states: "${e.message}".`;
  if (e.exception) {
    fields.exception = e.exception;
    notes += ` The exception is ${e.exception}`;
    notes += e.file ? `, thrown in ${e.file} line ${e.line}.` : ".";
  }
  if (e.root) {
    fields.application_root = e.root;
    notes += ` It gives the application's directory on the server as ${e.root}.`;
  }
  if (e.laravelVersion) fields.laravel_version = e.laravelVersion;
  if (e.phpVersion) {
    fields.php_version = e.phpVersion;
    notes += ` It names PHP ${e.phpVersion}${e.laravelVersion ? ` and Laravel ${e.laravelVersion}` : ""}.`;
  } else if (e.laravelVersion) {
    notes += ` It names Laravel ${e.laravelVersion}.`;
  }
  if (e.appEnv) {
    fields.app_env = e.appEnv;
    notes +=
      e.appEnv.toLowerCase() === "production"
        ? ` It reports APP_ENV as production, so this is the live environment and not a developer's copy.`
        : ` It reports APP_ENV as ${e.appEnv}.`;
  }
  notes +=
    `\n\nAn error page is a map of the application: the absolute paths of its source, the framework and ` +
    `PHP versions to look up advisories for, the query that failed with the values bound into it, and the ` +
    `code path each input reaches — which turns later testing from guesswork into reading. Where the ` +
    `handler prints the process environment, it hands over the credentials with it.` +
    `\n\nFix: set APP_DEBUG=false (and APP_ENV=production) in the deployment's environment, then ` +
    `\`php artisan config:clear\` if the configuration is cached. Laravel's own exception handler then ` +
    `answers "Server Error" and writes the trace to storage/logs instead.`;

  await record(`debug:${where.host}:${e.kind}`, {
    value: `Debug mode on (${where.host})`,
    types: ["laravel-debug"],
    notes,
    fields,
    flowId: where.flowId || undefined,
    location: where.flowId ? ("response_body" as Location) : undefined,
    detail: where.path,
  });

  await recordVersion(where.host, e.laravelVersion, "the debug error page", where.flowId);

  if (e.envNames.length > 0) {
    await record(`env:${where.host}`, {
      value: `Server environment in an error page (${where.host})`,
      types: ["laravel-debug"],
      notes:
        `The error page on ${where.host} prints the process environment, naming ${e.envNames.length} ` +
        `variables this plugin recognises: ${e.envNames.join(", ")}. Their values are on the page beside ` +
        `them — the database password, the mail and queue credentials and APP_KEY among them, wherever ` +
        `the deployment sets them in the environment, which is how every containerised Laravel app is ` +
        `configured.\n\nThis is what makes debug mode on a production host a credential leak rather than ` +
        `an information leak. Turn debug off, then treat every secret the page showed as known and rotate it.`,
      fields: { host: where.host, variables: e.envNames.join(", ") },
      flowId: where.flowId || undefined,
      location: where.flowId ? ("response_body" as Location) : undefined,
      detail: where.path,
    });
  }
  await recordAppKey(where, e.appKey, "the debug error page");
}

async function handleExposure(where: At, exposure: Exposure, body: string): Promise<void> {
  if (exposure.laravel) {
    await note(where, [{ why: `${exposure.label.toLowerCase()} on ${where.host}`, strong: true }]);
  }
  await record(`exposure:${where.host}:${exposure.id}`, {
    value: `${exposure.label} (${where.host})`,
    types: ["laravel-exposure"],
    notes: `${exposure.note}${exposure.extra ? " " + exposure.extra : ""}\n\nFix: ${exposure.fix}`,
    fields: { host: where.host, ...(exposure.fields || {}) },
    flowId: where.flowId || undefined,
    location: where.flowId ? ("response_body" as Location) : undefined,
    detail: where.path,
  });

  if (exposure.id === "env_file") {
    await recordAppKey(where, appKeyIn(body), "the exposed .env file");
  }
  if (exposure.id === "composer_file" && exposure.fields && exposure.fields.laravel_framework) {
    await recordVersion(where.host, exposure.fields.laravel_framework, "the exposed Composer manifest", where.flowId);
  }
}

/** recordAppKey records a leaked APP_KEY, hidden: it is a secret in itself. */
async function recordAppKey(where: At, key: string, from: string): Promise<void> {
  if (!key || settings.get<boolean>("record_app_key") === false) return;
  await record(`appkey:${key}`, {
    value: key,
    types: ["laravel-secret"],
    notes:
      `The application's APP_KEY, read from ${from} on ${where.host}. It is the key behind Laravel's ` +
      `Encrypter, so whoever has it can decrypt and forge every cookie the application sets — the session ` +
      `cookie included — read any column encrypted with it, and sign the URLs that signed routes trust. ` +
      `A forged encrypted payload has also been a route to remote code execution through PHP ` +
      `deserialization on applications that unserialize what they decrypt.` +
      `\n\nFix: find out what leaked it first, then rotate the key with \`php artisan key:generate\`. ` +
      `Rotating invalidates every existing session and makes data already encrypted with the old key ` +
      `unreadable, so anything encrypted at rest has to be re-encrypted in step.`,
    fields: { host: where.host, source: from },
    flowId: where.flowId || undefined,
    location: where.flowId ? ("response_body" as Location) : undefined,
    hidden: true,
  });
}

// ---- The active check ----------------------------------------------------------

/**
 * probe queues the active check for a host, if the user asked for it and
 * the host has been shown to run Laravel. It is called on every response
 * rather than only when the host is first recognised, so turning the
 * setting on mid-session still reaches the hosts already known.
 *
 * A host is asked once and once only. checkedHosts holds the hosts taken
 * in this run — including the one being asked right now — and the
 * engagement's own record (see runCheck) holds the ones asked before this
 * run started, so a reload, a restart or a second visit does not send the
 * same requests again.
 */
function probe(where: At): void {
  if (checkedHosts.has(where.host) || !laravelHosts.has(where.host)) return;
  if (settings.get<boolean>("active_probe") !== true) return;
  if (!inScope(where.origin + "/")) return;
  checkedHosts.add(where.host);
  chain = chain.then(() => runCheck(where)).catch((err) => log.error(`laravel: ${String(err)}`));
}

/**
 * runCheck asks one host for the paths the user listed, records what came
 * back, and writes down that the host has been checked.
 *
 * The record is written before the first request, not after the last one:
 * a check cut short by a reload or a closed engagement then counts as
 * done, which is the safer way round for requests sent at somebody else's
 * server. What it found is written back afterwards.
 */
async function runCheck(where: At): Promise<void> {
  const map = await loadKnown();
  if (!map) {
    checkedHosts.delete(where.host); // no engagement open: try again later
    return;
  }
  const before = map[where.host];
  if (before && before.checked) return; // asked in an earlier run

  const paths = (settings.get<string[]>("probe_paths") || []).filter((p) => String(p).trim() !== "");
  if (paths.length === 0) {
    checkedHosts.delete(where.host); // nothing to ask: let a filled-in list still run
    return;
  }

  const now: Known = {
    evidence: before ? before.evidence : "",
    seen: before ? before.seen : Date.now(),
    checked: Date.now(),
    origin: where.origin,
    asked: paths.length,
    found: [],
  };
  await remember(where.host, now);

  log.info(`checking ${where.origin} for ${paths.length} Laravel misconfigurations (once per host)`);
  for (const raw of paths) {
    const path = "/" + String(raw).trim().replace(/^\/+/, "");
    for (const found of await ask(where.origin, path)) {
      if (now.found.indexOf(found) < 0) now.found.push(found);
    }
  }

  await remember(where.host, now);
  await mark(where.origin, "laravel-checked", summarise(now));
  log.info(`checked ${where.origin}: ${summarise(now)}`);
}

/** How the check went, for the log and for the Explorer's note. */
function summarise(k: Known): string {
  const when = new Date(k.checked).toISOString().slice(0, 10);
  const asked = `${k.asked} path${k.asked === 1 ? "" : "s"} asked`;
  return `${when}: ${asked}, ${k.found.length > 0 ? `found ${k.found.join(", ")}` : "nothing found"}`;
}

/**
 * ask requests one path and reads the answer as if it had passed by,
 * answering with what it found there (for the host's record).
 */
async function ask(origin: string, path: string): Promise<string[]> {
  const url = origin + path;
  const wait = lastSend + gapMs - Date.now();
  if (wait > 0) await sleep(wait);
  lastSend = Date.now();

  let res: Response;
  try {
    // Recorded, so an active check is auditable in the Traffic list, but
    // not through the proxy: it needn't wait on interception.
    res = await http.send({ url, headers: { Accept: "*/*" } }, { record: true, timeoutMs: 15000 });
  } catch (err) {
    log.debug(`couldn't ask for ${url}: ${String(err)}`);
    return [];
  }

  const type = res.contentType();
  const body = res.isBinary() || res.size > maxBody() ? "" : res.text();
  const where: At = {
    host: hostOf(origin),
    scheme: origin.indexOf("https:") === 0 ? "https" : "http",
    method: "GET",
    path,
    status: res.status,
    flowId: res.flowId,
    origin,
  };

  const found: string[] = [];
  if (res.ok) {
    const exposure = exposureFor(path, type, body);
    if (exposure) {
      await handleExposure(where, exposure, body);
      found.push(exposure.id);
    }
  }
  // An error answer is worth reading whatever its status: asking for a path
  // that isn't there is how a debug error page turns up.
  const err = type.indexOf("json") >= 0 ? readJsonError(res.json()) : readHtmlError(body, body.toLowerCase());
  if (err) {
    await recordDebug(where, err);
    found.push(`debug mode (${err.kind})`);
  }
  return found;
}

// ---- What the engagement remembers ----------------------------------------------

/**
 * loadKnown reads the engagement's record once and keeps it, so the
 * lookup every response makes is a property read rather than a database
 * call. undefined means no engagement is open.
 */
async function loadKnown(): Promise<Record<string, Known> | undefined> {
  if (known) return known;
  try {
    known = (await storage.engagement.get<Record<string, Known>>(knownKey)) || {};
  } catch {
    return undefined;
  }
  return known;
}

/** What the engagement remembers about a host, if anything. */
async function remembered(host: string): Promise<Known | undefined> {
  const map = await loadKnown();
  return map ? map[host] : undefined;
}

/** remember writes a host's record back to the engagement. */
async function remember(host: string, record: Known): Promise<void> {
  const map = await loadKnown();
  if (!map) return;
  map[host] = record;
  const hosts = Object.keys(map);
  if (hosts.length > maxKnown) {
    // Oldest out: a long engagement should not fill the plugin's megabyte.
    hosts.sort((a, b) => (map[a].seen || 0) - (map[b].seen || 0));
    for (const host of hosts.slice(0, hosts.length - maxKnown)) delete map[host];
  }
  try {
    await storage.engagement.set(knownKey, map);
  } catch (e) {
    log.debug(`couldn't write down what was checked: ${String(e)}`);
  }
}

/**
 * mark leaves a note on the origin in the Entity Explorer, where the user
 * and other plugins can see it: that the host is Laravel, and that this
 * plugin has already been round it.
 */
async function mark(origin: string, name: string, value: string): Promise<void> {
  try {
    await entities.set(origin, name, value);
  } catch (e) {
    // The origin need not be in the Explorer: it is a note, not the record.
    log.debug(`couldn't note ${name} on ${origin}: ${String(e)}`);
  }
}

// ---- Odds and ends --------------------------------------------------------------

/** record keeps a finding once per run, and survives having nowhere to put it. */
async function record(key: string, draft: Parameters<typeof findings.record>[0]): Promise<void> {
  if (recorded.has(key)) return;
  recorded.add(key);
  try {
    await findings.record(draft);
  } catch (e) {
    recorded.delete(key);
    if (!warned) {
      warned = true;
      log.warn(`what the Laravel apps show isn't being recorded: ${e}`);
    }
  }
}

function at(flow: Flow): At {
  const host = flow.host.toLowerCase();
  return {
    host,
    scheme: flow.scheme,
    method: flow.method,
    path: flow.path,
    status: flow.status,
    flowId: flow.id,
    origin: `${flow.scheme}://${host}`,
  };
}

function siteValue(host: string): string {
  return `Laravel (${host})`;
}

/** The cookie attributes as sent, for the finding's fields. */
function attributesOf(secure: boolean, httpOnly: boolean, sameSite: string): string {
  const out: string[] = [];
  if (secure) out.push("Secure");
  if (httpOnly) out.push("HttpOnly");
  if (sameSite) out.push(`SameSite=${sameSite}`);
  return out.length > 0 ? out.join("; ") : "none";
}

/** Active work is only done on hosts a target covers. */
function inScope(url: string): boolean {
  return targets.list().length === 0 || !!targets.match(url);
}

function hostOf(origin: string): string {
  const sep = origin.indexOf("://");
  return sep < 0 ? origin.toLowerCase() : origin.slice(sep + 3).toLowerCase();
}

function maxBody(): number {
  const kb = Math.floor(Number(settings.get<number>("max_body_kb")));
  return (Number.isFinite(kb) && kb > 0 ? Math.min(kb, 16384) : 1024) * 1024;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
