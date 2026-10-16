// vue-spa: recognises a Vue single-page app and mines its Vite build.
//
// It watches the traffic the browser already loaded. A page's HTML tells it
// whether a Vue app (or Nuxt) is being served and whether Vite built the
// assets (src/detect.ts); the module bundles it pulls in may name a source
// map. On an in-scope host it then goes a step further, with requests of
// its own (so it is active, and disabled until enabled):
//
//   - it fetches any exposed source map (src/sourcemap.ts) and recovers the
//     application's own source files, the exact framework and build
//     versions the dependency paths reveal, and the URLs the source
//     references;
//   - it looks for Vite's build manifest (src/manifest.ts), which lists
//     every built chunk, stylesheet and asset.
//
// What it learns becomes findings — a Vue SPA, an exposed source map, an
// exposed build manifest, each framework version — and the hosts and URLs
// it turns up are added to the Entity Explorer, where off-target ones show
// under Targets → Related. Its own requests are recorded in the traffic
// list (the tester can see exactly what was fetched) and, like every
// plugin's traffic, go out through the configured upstream proxy chain.
//
// Work is remembered per engagement: a manifest is looked for once per
// origin, a map fetched once, whether the app restarts or not.

import { entities, findings, http, log, settings, storage, targets, text, type Flow, type Hooks, type Message, type Response } from "reproxy";
import { detectHtml, sourceMapRef, type Asset } from "./src/detect";
import { appSources, frameworkVersions, mapNamesVue, readSourceMap } from "./src/sourcemap";
import { MANIFEST_PATHS, readViteManifest } from "./src/manifest";
import { authorityOf, dirOf, originOf, resolveUrl } from "./src/url";

/** Engagement storage keys: origins whose manifest was looked for, maps fetched. */
const probedKey = "probed_origins";
const mapsKey = "fetched_maps";

/** DNSDumpster-style light pacing so active probes don't burst. */
let gapMs = 150;
let lastSend = 0;

// Session state, reset by load.
const spaHosts = new Set<string>(); // hosts recorded as a Vue SPA this run
const triedMaps = new Set<string>(); // map URLs fetched or in flight this run
const triedOrigins = new Set<string>(); // origins whose manifest was looked for this run
let chain: Promise<unknown> = Promise.resolve();

export function load(_e?: Hooks["plugin.on_load"]): void {
  spaHosts.clear();
  triedMaps.clear();
  triedOrigins.clear();
  chain = Promise.resolve();
}

/** For tests: the pause between active requests, and the work queued so far. */
export function setRequestGap(ms: number): void {
  gapMs = ms;
}
export function idle(): Promise<unknown> {
  return chain;
}

// ---- HTML: is this a Vue/Vite app, and what does it load? ---------------------

export function inspectHtml({ flow }: Hooks["traffic.on_response_received"]): void {
  const html = body(flow.response, kib("max_html_kb", 1024));
  if (!html) return;
  const facts = detectHtml(html, kib("max_html_kb", 1024));
  if (!facts.vue && !facts.vite) return;

  if (facts.vue && !spaHosts.has(flow.host)) {
    spaHosts.add(flow.host);
    recordSPA(flow, facts);
  }

  // The assets the page loads go in the Explorer whether or not we probe.
  for (const a of facts.assets) {
    const abs = resolveUrl(flow.url, a.ref);
    if (abs) addUrlSafe(abs, flow.id, `vue-spa:${a.kind}`);
  }

  if (!active(flow.url)) return;
  const origin = originOf(flow.url);
  if (origin && settings.get<boolean>("probe_vite_manifest") !== false) queue(() => probeManifest(origin, flow));
  if (settings.get<boolean>("fetch_source_maps") !== false) {
    for (const a of facts.assets) {
      if (a.kind !== "module" && a.kind !== "modulepreload") continue;
      const abs = resolveUrl(flow.url, a.ref);
      if (abs) queue(() => considerMap(abs + ".map", abs));
    }
  }
}

function recordSPA(flow: Flow, facts: ReturnType<typeof detectHtml>): void {
  const framework = facts.nuxt ? "Nuxt (Vue)" : "Vue.js";
  findings
    .record({
      value: `Vue single-page app on ${flow.host}`,
      types: ["vue-spa"],
      notes:
        `${framework} is served at ${flow.scheme}://${flow.host}. Detected from: ${facts.signals.join("; ")}. ` +
        `A single-page app runs its logic in the browser, so its routes, client-side checks and API calls are all in the JavaScript it ships — worth reading, especially if a source map or the Vite build manifest is exposed.`,
      fields: { host: flow.host, framework, build: facts.vite ? "Vite" : "unknown", signals: facts.signals.join(", ") },
      flowId: flow.id,
      location: "response_body",
    })
    .catch((err) => log.error(`recording the SPA: ${String(err)}`));
  log.info(`${framework} SPA at ${flow.host} (${facts.signals.join("; ")})`);
}

// ---- Bundles: follow an explicit source-map reference -------------------------

export function inspectScript({ flow }: Hooks["traffic.on_response_received"]): void {
  if (settings.get<boolean>("fetch_source_maps") === false || !active(flow.url)) return;
  const js = body(flow.response, kib("max_js_kb", 4096));
  if (!js) return;
  const ref = sourceMapRef(js);
  if (!ref) return;
  const abs = resolveUrl(dirOf(flow.url), ref);
  if (abs) queue(() => considerMap(abs, flow.url));
}

// ---- Source maps --------------------------------------------------------------

async function considerMap(mapUrl: string, fromUrl: string): Promise<void> {
  if (triedMaps.has(mapUrl)) return;
  triedMaps.add(mapUrl);
  let done: string[];
  try {
    done = (await storage.engagement.get<string[]>(mapsKey)) || [];
  } catch {
    triedMaps.delete(mapUrl);
    return; // no engagement open
  }
  if (done.indexOf(mapUrl) >= 0) return;

  const res = await get(mapUrl);
  if (res === undefined) {
    triedMaps.delete(mapUrl); // a transient failure: let another reference retry
    return;
  }
  // A definite answer, found or not, is remembered so it isn't re-requested.
  await remember(mapsKey, mapUrl);
  if (!res.ok) return;

  const maxBytes = Math.max(1, Math.floor(Number(settings.get<number>("max_map_mb")) || 12)) * 1024 * 1024;
  if (res.size > maxBytes) {
    await recordMap(mapUrl, fromUrl, res.flowId, undefined);
    return;
  }
  const map = readSourceMap(res.json());
  if (!map) return; // not a source map (a 404 page, an HTML error)
  await recordMap(mapUrl, fromUrl, res.flowId, map);

  if (settings.get<boolean>("add_discovered_urls") !== false) {
    const cap = clamp(settings.get<number>("max_urls_per_map"), 100, 0, 1000);
    if (cap > 0) {
      // The map is JSON, but the URLs worth having are buried in its source
      // content, so it is scanned as script text, not parsed as JSON.
      for (const u of text.urls(res.text(), mapUrl, "application/javascript", cap)) addUrlSafe(u, undefined, "vue-spa:source-map", fromUrl);
    }
  }
}

async function recordMap(mapUrl: string, fromUrl: string, flowId: number, map: ReturnType<typeof readSourceMap> | undefined): Promise<void> {
  let notes = `A JavaScript source map is served at ${mapUrl}. Source maps let an attacker recover the application's original, un-minified client source — its routes, client-side logic and API calls — so one on a production host is an information disclosure worth fixing (stop publishing .map files, or keep them behind access control).`;
  const fields: Record<string, string> = { source_map: mapUrl, referenced_by: fromUrl };

  if (map) {
    const app = appSources(map);
    const deps = frameworkVersions(map);
    // A client-rendered Vue SPA's HTML names nothing; the map confirms it.
    const host = authorityOf(fromUrl);
    if (host && !spaHosts.has(host) && mapNamesVue(map)) {
      spaHosts.add(host);
      findings
        .record({
          value: `Vue single-page app on ${host}`,
          types: ["vue-spa"],
          notes: `Vue.js is served at ${host}, confirmed from the source map ${mapUrl} (it names Vue in the build). The application's client source can be recovered from the map.`,
          fields: { host, framework: "Vue.js", build: "Vite", signals: `source map ${mapUrl}` },
          flowId: flowId || undefined,
          location: flowId ? "response_body" : undefined,
        })
        .catch((err) => log.error(`recording the SPA: ${String(err)}`));
    }
    fields.sources = String(map.sources.length);
    fields.application_files = String(app.length);
    fields.original_source = map.hasContent ? "included (sourcesContent)" : "paths only";
    if (app.length > 0) {
      const sample = app.slice(0, 20).map((s) => s.tidy);
      notes += `\n\nThe map names ${map.sources.length} source files, ${app.length} of them the application's own${app.length > sample.length ? ` (first ${sample.length} shown)` : ""}:\n- ` + sample.join("\n- ");
    }
    if (map.hasContent) notes += `\n\nIt also carries the original source text (sourcesContent), so the client source can be read directly.`;
    for (const d of deps) recordVersion(d.name, d.version, `the source map ${mapUrl}`, flowId);
    log.info(`source map exposed: ${mapUrl} (${app.length} app files, ${deps.length} framework versions)`);
  } else {
    log.info(`source map exposed (not parsed, too large): ${mapUrl}`);
    notes += `\n\nThe map is larger than the parse limit, so it was recorded as exposed but not read; raise "Largest source map parsed" to extract from it.`;
  }

  try {
    await findings.record({ value: mapUrl, types: ["source-map"], notes, fields, flowId: flowId || undefined, location: flowId ? "response_body" : undefined });
  } catch (err) {
    log.error(`recording the source map: ${String(err)}`);
  }
}

// ---- Vite build manifest ------------------------------------------------------

async function probeManifest(origin: string, flow: Flow): Promise<void> {
  if (triedOrigins.has(origin)) return;
  triedOrigins.add(origin);
  let done: Record<string, boolean>;
  try {
    done = (await storage.engagement.get<Record<string, boolean>>(probedKey)) || {};
  } catch {
    triedOrigins.delete(origin);
    return;
  }
  if (done[origin]) return;

  for (const path of MANIFEST_PATHS) {
    const u = origin + path;
    const res = await get(u);
    if (res === undefined) {
      triedOrigins.delete(origin); // transient: retry next time
      return;
    }
    if (!res.ok) continue;
    const vm = readViteManifest(res.json());
    if (!vm) continue;
    await recordManifest(u, vm, flow, res.flowId);
    await remember(probedKey, origin, true);
    return;
  }
  await remember(probedKey, origin, true); // tried every path, none was a manifest
}

async function recordManifest(url: string, vm: ReturnType<typeof readViteManifest> & object, flow: Flow, flowId: number): Promise<void> {
  const siteRoot = originOf(url) + "/";
  let added = 0;
  for (const file of vm.files) {
    // Manifest paths are relative to the build's output root, which is the
    // site root they are served from.
    const abs = resolveUrl(siteRoot, file.replace(/^\/+/, ""));
    if (abs) {
      addUrlSafe(abs, undefined, "vue-spa:manifest", flow.url);
      added++;
    }
  }
  try {
    await findings.record({
      value: url,
      types: ["build-manifest"],
      notes:
        `Vite's build manifest is served at ${url}. It lists every built file of the front end — ${vm.files.length} chunks, stylesheets and assets — and names the application's entry points${vm.entries.length ? `: ${vm.entries.slice(0, 10).join(", ")}` : ""}. A published build manifest maps out the whole client application for an attacker; it is meant for the server, not the public.`,
      fields: { build_manifest: url, files: String(vm.files.length), entries: vm.entries.slice(0, 20).join(", ") },
      flowId: flowId || undefined,
      location: flowId ? "response_body" : undefined,
    });
    log.info(`Vite build manifest exposed: ${url} (${vm.files.length} files, ${added} added to the Explorer)`);
  } catch (err) {
    log.error(`recording the build manifest: ${String(err)}`);
  }
}

// ---- Versions -----------------------------------------------------------------

function recordVersion(name: string, version: string, where: string, flowId: number): void {
  findings
    .record({
      value: `${name} ${version}`,
      types: ["tech-version"],
      notes: `${name} ${version} is in use, from ${where}. Knowing the exact version lets an attacker look up the vulnerabilities it has; check it against its advisories, and keep it up to date.`,
      fields: { package: name, version, evidence: where },
      flowId: flowId || undefined,
      location: flowId ? "response_body" : undefined,
    })
    .catch((err) => log.error(`recording ${name} ${version}: ${String(err)}`));
}

// ---- Helpers ------------------------------------------------------------------

/** Put a URL in the Explorer, swallowing the odd bad URL rather than failing the hook. */
function addUrlSafe(url: string, flowId: number | undefined, detail: string, from?: string): void {
  entities.addUrl({ url, flowId, from, detail }).catch(() => undefined);
}

/** A GET to the target, recorded in the traffic list; undefined (logged) on a transport failure. */
async function get(url: string): Promise<Response | undefined> {
  const wait = lastSend + gapMs - Date.now();
  if (wait > 0) await sleep(wait);
  lastSend = Date.now();
  try {
    return await http.send({ url, headers: { Accept: "*/*" } }, { record: true, timeoutMs: 20000 });
  } catch (err) {
    log.error(`couldn't fetch ${url}: ${String(err)}`);
    return undefined;
  }
}

/** Active work (fetching, probing) is only done on hosts a target covers. */
function active(url: string): boolean {
  return targets.list().length === 0 || !!targets.match(url);
}

/** A message's text, when it is text and within the byte cap; "" otherwise. */
function body(msg: Message, maxBytes: number): string {
  if (msg.empty || msg.size > maxBytes || msg.isBinary()) return "";
  return msg.text();
}

async function remember(key: string, value: string, flag?: boolean): Promise<void> {
  try {
    if (flag !== undefined) {
      const m = (await storage.engagement.get<Record<string, boolean>>(key)) || {};
      m[value] = flag;
      await storage.engagement.set(key, m);
    } else {
      const list = (await storage.engagement.get<string[]>(key)) || [];
      if (list.indexOf(value) < 0) await storage.engagement.set(key, [...list, value]);
    }
  } catch {
    // no engagement open; nothing to remember
  }
}

/** Run fn after everything queued before it, so active probes go one at a time. */
function queue(fn: () => Promise<void>): void {
  chain = chain.then(fn).catch((err) => log.error(`vue-spa: ${String(err)}`));
}

function kib(key: string, dflt: number): number {
  return Math.max(1, Math.floor(Number(settings.get<number>(key)) || dflt)) * 1024;
}

function clamp(v: unknown, dflt: number, min: number, max: number): number {
  const n = Math.floor(Number(v));
  return Math.min(Math.max(Number.isFinite(n) && v !== undefined && v !== null ? n : dflt, min), max);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
