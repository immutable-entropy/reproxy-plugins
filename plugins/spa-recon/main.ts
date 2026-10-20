// spa-recon: recognises a single-page app — Vue/Nuxt, React/Next,
// Svelte/SvelteKit or Angular (src/frameworks.ts) — and mines the build
// behind it.
//
// It watches the traffic the browser already loaded. A page's HTML tells it
// which framework is being served and whether a bundler (Vite, or any build
// that preloads hashed modules) made the assets (src/detect.ts); the module
// bundles it pulls in may name a source map. On an in-scope host it then
// goes a step further, with requests of its own (so it is active, and
// disabled until enabled):
//
//   - it fetches any exposed source map (src/sourcemap.ts) and recovers the
//     application's own source files, the exact framework and build
//     versions the dependency paths reveal, and the URLs the source
//     references;
//   - it looks for Vite's build manifest (src/manifest.ts), which lists
//     every built chunk, stylesheet and asset.
//
// What it learns becomes findings — the SPA and its framework, an exposed
// source map, an exposed build manifest, each framework version — and the
// hosts and URLs it turns up are added to the Entity Explorer, where
// off-target ones show under Targets → Related. Its own requests are
// recorded in the traffic list (the tester can see exactly what was
// fetched) and, like every plugin's traffic, go out through the configured
// upstream proxy chain.
//
// Work is remembered per engagement: a manifest is looked for once per
// origin, a map fetched once, whether the app restarts or not.

import { entities, files, findings, http, log, settings, storage, targets, text, type ActionHandler, type FileDraft, type Flow, type Hooks, type Message, type Response } from "reproxy";
import { anyFramework, detectHtml, sourceMapRef, type Asset } from "./src/detect";
import { allDeps, appSources, frameworkVersions, mapFramework, readSourceMap, type SourceMap } from "./src/sourcemap";
import { label, nameOf } from "./src/frameworks";
import { recoverFiles } from "./src/reconstruct";
import { MANIFEST_PATHS, readViteManifest } from "./src/manifest";
import { authorityOf, dirOf, originOf, resolveUrl } from "./src/url";

/** Engagement storage keys: origins whose manifest was looked for, maps fetched. */
const probedKey = "probed_origins";
const mapsKey = "fetched_maps";

/** At most this many fetched URLs are remembered; the oldest are dropped. */
const maxRemembered = 2000;

/** DNSDumpster-style light pacing so active probes don't burst. */
let gapMs = 150;
let lastSend = 0;

// Session state, reset by load.
const spaHosts = new Set<string>(); // hosts recorded as an SPA this run
const triedMaps = new Set<string>(); // map URLs fetched or in flight this run
const triedOrigins = new Set<string>(); // origins whose manifest was looked for this run
let chain: Promise<unknown> = Promise.resolve();

export function load(_e?: Hooks["plugin.on_load"]): void {
  spaHosts.clear();
  triedMaps.clear();
  triedOrigins.clear();
  chain = Promise.resolve();
}

/**
 * onEngagement starts again when another engagement is opened. What was
 * fetched belongs to the engagement it was fetched for — along with the
 * findings and the recovered files it produced — so the new one is worked
 * out from its own record rather than from the last one's.
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

// ---- HTML: is this an SPA, and what does it load? -----------------------------

export function inspectHtml({ flow }: Hooks["traffic.on_response_received"]): void {
  const html = body(flow.response, kib("max_html_kb", 1024));
  if (!html) return;
  const facts = detectHtml(html, kib("max_html_kb", 1024));
  if (!anyFramework(facts) && !facts.bundled) return;

  if (anyFramework(facts) && !spaHosts.has(flow.host)) {
    spaHosts.add(flow.host);
    recordSPA(flow, facts);
  }

  // The assets the page loads go in the Explorer whether or not we probe.
  for (const a of facts.assets) {
    const abs = resolveUrl(flow.url, a.ref);
    if (abs) addUrlSafe(abs, flow.id, `spa-recon:${a.kind}`);
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
  const framework = facts.frameworks.length ? label(facts.frameworks[0]) : "Unknown";
  findings
    .record({
      value: `Single-page app (${framework}) on ${flow.host}`,
      types: ["spa"],
      notes:
        `${framework} is served at ${flow.scheme}://${flow.host}. Detected from: ${facts.signals.join("; ")}. ` +
        `A single-page app runs its logic in the browser, so its routes, client-side checks and API calls are all in the JavaScript it ships — worth reading, especially if a source map or the build manifest is exposed.`,
      fields: { host: flow.host, framework, build: facts.vite ? "Vite" : facts.bundled ? "bundler" : "unknown", signals: facts.signals.join(", ") },
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
  // Un-webpack the map to the engagement's recovered files, when asked and
  // the map carries the source; the finding then links to what was written.
  const recovered = settings.get<boolean>("unpack_source_maps") !== false && map.hasContent
    ? await unpackMap(mapUrl, map, fromUrl, res.flowId)
    : undefined;
  await recordMap(mapUrl, fromUrl, res.flowId, map, recovered);

  if (settings.get<boolean>("add_discovered_urls") !== false) {
    const cap = clamp(settings.get<number>("max_urls_per_map"), 100, 0, 1000);
    if (cap > 0) {
      // The map is JSON, but the URLs worth having are buried in its source
      // content, so it is scanned as script text, not parsed as JSON.
      for (const u of text.urls(res.text(), mapUrl, "application/javascript", cap)) addUrlSafe(u, undefined, "spa-recon:source-map", fromUrl);
    }
  }
}

async function recordMap(mapUrl: string, fromUrl: string, flowId: number, map: ReturnType<typeof readSourceMap> | undefined, recovered?: Recovered): Promise<void> {
  let notes = `A JavaScript source map is served at ${mapUrl}. Source maps let an attacker recover the application's original, un-minified client source — its routes, client-side logic and API calls — so one on a production host is an information disclosure worth fixing (stop publishing .map files, or keep them behind access control).`;
  const fields: Record<string, string> = { source_map: mapUrl, referenced_by: fromUrl };

  if (map) {
    const app = appSources(map);
    const deps = frameworkVersions(map);
    // A client-rendered SPA's HTML names nothing; the map confirms the
    // framework by what it imports from node_modules.
    const host = authorityOf(fromUrl);
    const fw = mapFramework(map);
    if (host && fw && !spaHosts.has(host)) {
      spaHosts.add(host);
      const framework = nameOf(fw);
      findings
        .record({
          value: `Single-page app (${framework}) on ${host}`,
          types: ["spa"],
          notes: `${framework} is served at ${host}, confirmed from the source map ${mapUrl} (it names ${framework} in the build). The application's client source can be recovered from the map.`,
          fields: { host, framework, build: "bundler", signals: `source map ${mapUrl}` },
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
    if (settings.get<boolean>("record_dependencies") !== false) recordDependencies(map, mapUrl, flowId);
    log.info(`source map exposed: ${mapUrl} (${app.length} app files, ${deps.length} framework versions)`);
  } else {
    log.info(`source map exposed (not parsed, too large): ${mapUrl}`);
    notes += `\n\nThe map is larger than the parse limit, so it was recorded as exposed but not read; raise "Largest source map parsed" to extract from it.`;
  }

  if (recovered && recovered.fileIds.length > 0) {
    fields.recovered_files = String(recovered.files);
    fields.recovered_directory = recovered.dir;
    notes += `\n\nThe application's source was recovered to the engagement's recovered files (${recovered.files} files under ${recovered.dir}); the links below open them. `;
    if (recovered.urls > 0) {
      fields.urls_found = String(recovered.urls);
      fields.urls_in_scope = String(recovered.inScope);
      notes += `Mining the recovered source turned up ${recovered.urls} URLs it references, ${recovered.inScope} of them in scope`;
      if (recovered.sample.length > 0) {
        notes += `:\n- ` + recovered.sample.join("\n- ") + (recovered.inScope > recovered.sample.length ? "\n- …" : "");
      } else {
        notes += ".";
      }
      notes += `\n\nThe in-scope URLs are in the Entity Explorer; all discovered URLs are there too (off-target ones under Targets → Related).`;
    }
  }

  try {
    await findings.record({
      value: mapUrl,
      types: ["source-map"],
      notes,
      fields,
      flowId: flowId || undefined,
      location: flowId ? "response_body" : undefined,
      files: recovered ? recovered.fileIds : undefined,
    });
  } catch (err) {
    log.error(`recording the source map: ${String(err)}`);
  }
}

// ---- Un-webpacking: recover the app source to disk ----------------------------

/** What one unpackMap wrote and found, for the finding and the action result. */
interface Recovered {
  /** The recovered files' ids, for linking the finding to them. */
  fileIds: number[];
  /** How many files were written. */
  files: number;
  /** The directory they were written under. */
  dir: string;
  /** URLs mined from the recovered source, and how many are in scope. */
  urls: number;
  inScope: number;
  /** A sample of the in-scope URLs, for the finding's notes. */
  sample: string[];
}

// unpackMap reconstructs the application's own source files from a map and
// writes them to the engagement's recovered files (files.addAll, which
// creates a File object per file and keeps them inside the recovered-files
// root whatever the path says), then mines each recovered file for the URLs
// it references — resolved against the site, so a relative "/api/..." becomes
// a real URL. Only the application's own source is written; a dependency's
// source is not (its version is recorded as a finding instead). Returns
// undefined when the map carries no application source to recover.
async function unpackMap(mapUrl: string, map: SourceMap, fromUrl: string, flowId: number): Promise<Recovered | undefined> {
  const appFiles = recoverFiles(map).filter((f) => f.app);
  if (appFiles.length === 0) return undefined;

  // Lay the files out under the map's own host and path, so two maps never
  // collide; core cleans the path and keeps it inside the recovered root.
  const base = mapUrl.replace(/^https?:\/\//i, "").replace(/[?#].*$/, "") + "/";
  const drafts: FileDraft[] = appFiles.map((f) => ({
    path: base + f.path,
    content: f.content,
    kind: "source-map",
    batch: mapUrl,
    batchLabel: `source map ${mapUrl}`,
    flowId: flowId || undefined,
    url: fromUrl,
    notes: `Recovered from the source map ${mapUrl}.`,
  }));

  let rec;
  try {
    rec = await files.addAll(drafts);
  } catch (err) {
    log.error(`${mapUrl}: couldn't write the recovered source: ${String(err)}`);
    return undefined;
  }

  // Mine the recovered source for the URLs it calls. Every URL goes to the
  // Explorer (core scopes and suppresses it); the in-scope ones are counted
  // and sampled for the finding.
  const origin = originOf(fromUrl) || originOf(mapUrl);
  const seen = new Set<string>();
  const sample: string[] = [];
  let urls = 0;
  let inScope = 0;
  const overall = 5000;
  for (const f of appFiles) {
    if (urls >= overall) break;
    for (const u of text.urls(f.content, origin, "application/javascript", 300)) {
      if (seen.has(u)) continue;
      seen.add(u);
      addUrlSafe(u, flowId || undefined, `spa-recon:recovered ${f.path}`, fromUrl);
      urls++;
      if (targets.match(u)) {
        inScope++;
        if (sample.length < 20) sample.push(u);
      }
      if (urls >= overall) break;
    }
  }

  log.info(`unpacked ${rec.recorded.length} source files from ${mapUrl} to ${rec.dir}; mined ${urls} URLs (${inScope} in scope)`);
  return { fileIds: rec.recorded.map((r) => r.id), files: rec.files, dir: rec.dir, urls, inScope, sample };
}

// recordDependencies records every bundled dependency a map reveals (and its
// version) as a Technology Version finding. Their source is not written to
// disk, so the finding is the record of what is shipped. Frameworks are left
// to frameworkVersions, which gives them a richer note.
function recordDependencies(map: SourceMap, mapUrl: string, flowId: number): void {
  const frameworks = new Set(frameworkVersions(map).map((d) => d.name));
  const cap = clamp(settings.get<number>("max_dependency_findings"), 200, 0, 5000);
  if (cap <= 0) return;
  let n = 0;
  for (const d of allDeps(map)) {
    if (frameworks.has(d.name)) continue;
    if (n >= cap) {
      log.info(`${mapUrl}: more than ${cap} dependencies; raise "Most dependency findings per source map" to record them all`);
      break;
    }
    n++;
    findings
      .record({
        value: `${d.name} ${d.version}`,
        types: ["tech-version"],
        notes: `${d.name} ${d.version} is bundled into the front end, revealed by the source map ${mapUrl}. Knowing the exact version lets an attacker look up the vulnerabilities it has; check it against its advisories and keep it up to date.`,
        fields: { package: d.name, version: d.version, evidence: `the source map ${mapUrl}`, dependency: "true" },
        flowId: flowId || undefined,
        location: flowId ? "response_body" : undefined,
      })
      .catch((err) => log.error(`recording ${d.name} ${d.version}: ${String(err)}`));
  }
}

// ---- Action: recover the source from a map ------------------------------------

// Run from the traffic list's right-click menu on a bundle or a .map. It does
// the same un-webpacking the passive path does when the setting is on — write
// the application's source to the engagement's recovered files, mine each for
// the URLs it calls, and record the exposed-map finding linked to the files —
// so it stands on its own if the passive hook never ran or the setting is off.
export const recoverSources: ActionHandler = async ({ flow }) => {
  const got = await obtainMap(flow);
  if (!got) return "No source map found for this flow (no sourcesContent to recover).";
  const { mapUrl, map, fromUrl, flowId } = got;

  const recovered = await unpackMap(mapUrl, map, fromUrl, flowId);
  if (!recovered) return `${mapUrl} is a source map, but carries no embedded application source (sourcesContent) to recover.`;

  // Record the exposed-map finding (with the file links and discovered URLs),
  // the versions and the framework confirmation, the same way the passive
  // path would, so a deliberate run is complete.
  await recordMap(mapUrl, fromUrl, flowId, map, recovered);

  return `Recovered ${recovered.files} application source files to ${recovered.dir}; added ${recovered.urls} URLs to the Explorer (${recovered.inScope} in scope).`;
};

/** The map behind a flow: its own body if it is one, else the map its bundle names. */
async function obtainMap(flow: Flow): Promise<{ mapUrl: string; map: SourceMap; fromUrl: string; flowId: number } | undefined> {
  const maxMapBytes = Math.max(1, Math.floor(Number(settings.get<number>("max_map_mb")) || 12)) * 1024 * 1024;
  const self = body(flow.response, maxMapBytes);
  // The flow may already be the .map.
  const asMap = self ? readSourceMap(parse(self)) : undefined;
  if (asMap) return { mapUrl: flow.url, map: asMap, fromUrl: flow.url, flowId: flow.id };

  // Otherwise it is a bundle: follow its sourceMappingURL, or try url + ".map".
  const refs: string[] = [];
  const ref = self ? sourceMapRef(self) : undefined;
  if (ref) {
    const abs = resolveUrl(dirOf(flow.url), ref);
    if (abs) refs.push(abs);
  }
  refs.push(flow.url.replace(/[?#].*$/, "") + ".map");

  for (const mapUrl of refs) {
    const res = await get(mapUrl);
    if (!res || !res.ok) continue;
    const map = readSourceMap(res.json());
    if (map) return { mapUrl, map, fromUrl: flow.url, flowId: res.flowId };
  }
  return undefined;
}

/** JSON.parse that returns undefined rather than throwing on bad input. */
function parse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
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
      addUrlSafe(abs, undefined, "spa-recon:manifest", flow.url);
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
      if (list.indexOf(value) >= 0) return;
      // Bounded: the plugin's storage is a megabyte, and a store that
      // can't be written is a store that forgets — which would mean
      // fetching the same files from the site all over again.
      const kept = list.length >= maxRemembered ? list.slice(list.length - maxRemembered + 1) : list;
      await storage.engagement.set(key, [...kept, value]);
    }
  } catch {
    // no engagement open; nothing to remember
  }
}

/** Run fn after everything queued before it, so active probes go one at a time. */
function queue(fn: () => Promise<void>): void {
  chain = chain.then(fn).catch((err) => log.error(`spa-recon: ${String(err)}`));
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
