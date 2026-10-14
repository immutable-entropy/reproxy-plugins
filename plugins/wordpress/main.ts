// wordpress: works out what a WordPress site is built from, and records it.
//
// It watches the Map rather than the traffic. Every time an endpoint is put
// there — by a request, or by a link core found in a response — this plugin
// looks at what that endpoint and the responses behind it say about the
// site: the core version, the plugins and themes whose assets it serves, the
// REST namespaces plugins register, and the accounts it names. Each becomes
// a finding linked to the request it was seen in.
//
// Watching the Map rather than the traffic is deliberate. The Map already
// holds one row per endpoint however many times it was requested, so the
// work happens once per *new thing seen* instead of once per request, and
// the plugin never sits on the proxy's path. It is also entirely passive:
// nothing here sends a request, so a site learns nothing about us. What it
// reports is only what the traffic already carried.
//
// Nothing is claimed with more confidence than the evidence allows. A ?ver=
// is whatever the code that enqueued an asset passed, so a version matching
// the core version is reported as unknown rather than as the plugin's; see
// src/fingerprint.ts.

import { findings, flows, log, settings, type Endpoint, type Flow, type Hooks, type Location } from "reproxy";
import { fromHeaders, fromPath, looksWordPress, read, versionOf, type Fact } from "./src/fingerprint";
import { readRest, routeOf } from "./src/rest";

/** One fact, and where it was seen. */
interface Sighting {
  /** The host it is about: the endpoint's, or that of the page it was read in. */
  host: string;
  fact: Fact;
  flowId?: number;
  location?: Location;
}

/** What showed a host to be WordPress. */
interface Evidence {
  why: string;
  flowId?: number;
}

/** The most responses read for one endpoint event. */
const maxPages = 3;
/** Responses bigger than this are left alone. */
const maxBody = 4 * 1024 * 1024;

// Session state. Findings merge on their value, so nothing is lost by
// forgetting this between runs; it only keeps the plugin from doing the same
// work twice while it runs.
const reported = new Set<string>(); // findings already recorded
const scanned = new Set<number>(); // flows already read
const wpSites = new Set<string>(); // hosts shown to be WordPress
const coreVersions: Record<string, string> = {}; // host → core version seen
const versions: Record<string, string> = {}; // kind:host:slug → version recorded
let warned = false;

export function init({ reason }: Hooks["plugin.on_load"]): void {
  reported.clear();
  scanned.clear();
  wpSites.clear();
  warned = false;
  for (const k of Object.keys(coreVersions)) delete coreVersions[k];
  for (const k of Object.keys(versions)) delete versions[k];
  log.debug(`watching the Map for WordPress sites (${reason})`);
}

export async function onEndpoint({ endpoint }: Hooks["endpoint.on_discovered"]): Promise<void> {
  const shown: Record<string, Evidence> = {};
  const show = (host: string, why: string, flowId?: number): void => {
    if (why && !shown[host]) shown[host] = { why, flowId };
  };
  const found: Sighting[] = [];

  // The endpoint itself. Its path is the templated one, which keeps a plugin
  // slug (a slug doesn't look like an identifier), and its examples are the
  // concrete paths seen.
  for (const path of [endpoint.path].concat(endpoint.examples)) {
    const fp = looksWordPress(path);
    show(endpoint.host, fp ? `the path ${path}` : "");
    for (const fact of fromPath(path)) found.push({ host: endpoint.host, fact });
  }

  // Then the responses behind it: the requests made to it, and the page it
  // was discovered in — which may be another host's, so each flow's facts
  // are attributed to its own host.
  if (settings.get<boolean>("read_pages")) {
    for (const flow of pages(endpoint)) {
      scanned.add(flow.id);
      for (const s of readFlow(flow, show)) found.push(s);
    }
  }

  // A host nothing has shown to be WordPress is left alone: this plugin says
  // nothing about the rest of an engagement's traffic.
  for (const host of Object.keys(shown)) {
    if (wpSites.has(host)) continue;
    wpSites.add(host);
    await site(host, shown[host]);
  }

  // Core first: a plugin asset whose ?ver= is the core version is not
  // stating the plugin's own version, and that has to be known to tell.
  const facts = best(found);
  for (const s of facts) {
    if (s.fact.kind === "core") await recordCore(s);
  }
  for (const s of facts) {
    if (s.fact.kind !== "core") await recordPart(s);
  }
}

/**
 * best collapses the sightings of one event: one per kind, host and name,
 * keeping the one that says the most (see better), so a slug read from a
 * path doesn't stand in for the same slug read from the page that states its
 * version.
 */
function best(found: Sighting[]): Sighting[] {
  const out: Sighting[] = [];
  const at: Record<string, number> = {};
  for (const s of found) {
    const key = `${s.fact.kind}:${s.host}:${s.fact.name}`;
    const have = at[key];
    if (have === undefined) {
      at[key] = out.length;
      out.push(s);
      continue;
    }
    if (better(s, out[have])) out[have] = s;
  }
  return out;
}

/**
 * better compares two sightings of the same thing: one that states a version
 * beats one that doesn't, and one that can be linked to the request it was
 * seen in beats a bare path.
 */
function better(s: Sighting, than: Sighting): boolean {
  if (!!s.fact.version !== !!than.fact.version) return !!s.fact.version;
  return !than.flowId && !!s.flowId;
}

/** pages picks the responses to read for an endpoint, newest requests first. */
function pages(e: Endpoint): Flow[] {
  const ids: number[] = [];
  const want = (id: number): void => {
    if (id && ids.length < maxPages && ids.indexOf(id) < 0 && !scanned.has(id)) ids.push(id);
  };
  for (let i = e.flowIds.length - 1; i >= 0; i--) want(e.flowIds[i]);
  for (const link of e.links) want(link.fromFlowId);

  const out: Flow[] = [];
  for (const id of ids) {
    const flow = flows.get(id);
    if (flow && flow.response.size <= maxBody) out.push(flow);
  }
  return out;
}

/** readFlow reads one response: its request, its headers and its body. */
function readFlow(flow: Flow, show: (host: string, why: string, flowId?: number) => void): Sighting[] {
  const host = flow.host.toLowerCase();
  const out: Sighting[] = [];
  const fp = looksWordPress(flow.path);
  show(host, fp ? `the request ${flow.method} ${flow.path}` : "", flow.id);

  // A request to an asset states that asset's version in its query.
  for (const fact of fromPath(flow.path, versionOf(flow.query))) {
    out.push({ host, fact, flowId: flow.id });
  }
  if (flow.response.empty) return out;
  show(host, fromHeaders(flow.response.headers()), flow.id);

  const type = flow.response.contentType();
  if (flow.response.isBinary()) return out;

  const route = routeOf(flow.path, flow.query);
  if (route && type.indexOf("json") >= 0) {
    const body = flow.response.json();
    if (body !== undefined) {
      for (const fact of readRest(route, body)) {
        show(host, `a reply from the REST API (${route})`, flow.id);
        out.push({ host, fact, flowId: flow.id, location: "response_body" });
      }
    }
  }
  if (!readable(type)) return out;

  const reading = read(flow.response.text());
  show(host, reading.fingerprint, flow.id);
  for (const fact of reading.facts) {
    out.push({ host, fact, flowId: flow.id, location: "response_body" });
  }
  return out;
}

function readable(type: string): boolean {
  return (
    type === "" ||
    type.indexOf("text/") === 0 ||
    type.indexOf("html") >= 0 ||
    type.indexOf("xml") >= 0 ||
    type.indexOf("json") >= 0 ||
    type.indexOf("javascript") >= 0
  );
}

/** site records that a host runs WordPress, with what showed it. */
async function site(host: string, e: Evidence): Promise<void> {
  await record(`site:${host}`, {
    value: siteValue(host),
    types: ["wordpress"],
    notes:
      `${host} runs WordPress — ${e.why}. What follows about its plugins, themes and accounts ` +
      `was read from traffic that had already passed through; nothing was requested.`,
    fields: [{ key: "host", value: host }],
    flowId: e.flowId,
  });
}

/**
 * recordCore records a core version. It merges into the site's finding
 * rather than making its own, so a site is one row whose notes gain each
 * version seen.
 */
async function recordCore(s: Sighting): Promise<void> {
  if (!wpSites.has(s.host)) return;
  const version = s.fact.version;
  if (!version) return; // the site finding already says it is WordPress
  coreVersions[s.host] = version;
  await record(`core:${s.host}:${version}`, {
    value: siteValue(s.host),
    types: ["wordpress"],
    notes: `Core version ${version}, from ${s.fact.evidence}. Compare it with the current WordPress release.`,
    fields: [
      { key: "host", value: s.host },
      { key: "core version", value: version },
    ],
    flowId: s.flowId,
    location: s.location,
  });
}

/** recordPart records a plugin, a theme, a REST namespace or an account. */
async function recordPart(s: Sighting): Promise<void> {
  if (!wpSites.has(s.host)) return;
  const f = s.fact;
  switch (f.kind) {
    case "plugin":
    case "theme": {
      const key = `${f.kind}:${s.host}:${f.name}`;
      const core = coreVersions[s.host];
      // A version equal to the core version is what WordPress passes when
      // the code enqueuing the asset gave none: it says nothing about the
      // plugin.
      const own = f.version && f.version !== core ? f.version : "";
      if (!own && versions[key]) return; // a version is already recorded
      if (own) versions[key] = own;

      // One finding per plugin per host, whatever turns up later: a version
      // read after the plugin was first seen merges into it as another note,
      // rather than standing beside it as a second row. An upgrade between
      // engagements therefore reads as a history.
      let notes = `${s.host} serves a ${f.kind} named ${f.name} — ${f.evidence}.`;
      if (own) {
        notes += ` It states version ${own}; check that against the current release of the ${f.kind}.`;
      } else if (f.version) {
        notes += ` Its assets carry ?ver=${f.version}, which is the core version, so the ${f.kind}'s own version is not stated.`;
      } else {
        notes += ` No version was stated.`;
      }
      await record(`${key}:${own}`, {
        value: `${f.name} (${s.host})`,
        types: [`wordpress-${f.kind}`],
        notes,
        fields: own
          ? [{ key: "host", value: s.host }, { key: "slug", value: f.name }, { key: "version", value: own }]
          : [{ key: "host", value: s.host }, { key: "slug", value: f.name }],
        flowId: s.flowId,
        location: s.location,
      });
      return;
    }
    case "user": {
      if (!settings.get<boolean>("record_users")) return;
      await record(`user:${s.host}:${f.name.toLowerCase()}`, {
        value: `${f.name} (${s.host})`,
        types: ["wordpress-user"],
        notes:
          `${s.host} names the account ${f.name} without being asked: ${f.evidence}. A username ` +
          `narrows a password attempt against /wp-login.php or xmlrpc.php, so a site that lists its ` +
          `accounts has given away half of each login.`,
        fields: [{ key: "host", value: s.host }, { key: "account", value: f.name }],
        flowId: s.flowId,
        location: s.location,
      });
      return;
    }
    case "rest-namespace": {
      if (!settings.get<boolean>("record_rest_namespaces")) return;
      // Recorded as the plugin it is, under the same value its assets would
      // give, so a plugin found both ways is one finding: jetpack's assets
      // and its jetpack/* namespaces are the same plugin.
      await record(`namespace:${s.host}:${f.name}`, {
        value: `${f.name} (${s.host})`,
        types: ["wordpress-plugin"],
        notes:
          `The REST API on ${s.host} registers the namespace ${f.name}, which core does not: a ` +
          `plugin added it, and its routes are worth reading even when the plugin serves no assets ` +
          `to give its name away. Seen in ${f.evidence}.`,
        fields: [{ key: "host", value: s.host }, { key: "rest namespace", value: f.name }],
        flowId: s.flowId,
        location: s.location,
      });
      return;
    }
  }
}

function siteValue(host: string): string {
  return `WordPress (${host})`;
}

/** record keeps a finding once per session, and survives having nowhere to put it. */
async function record(key: string, draft: Parameters<typeof findings.record>[0]): Promise<void> {
  if (reported.has(key)) return;
  reported.add(key);
  try {
    await findings.record(draft);
  } catch (e) {
    reported.delete(key);
    if (!warned) {
      warned = true;
      log.warn(`what the WordPress sites show isn't being recorded: ${e}`);
    }
  }
}
