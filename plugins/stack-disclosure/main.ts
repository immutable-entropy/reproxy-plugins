// stack-disclosure: flags what a response's headers give away about the
// stack the site runs on.
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
// switch off with the one setting the notes name.
//
// Those headers are on every response, so each disclosure is recorded once
// per host per run, with notes that don't name the request: a finding then
// gains one sighting per host rather than one per response. Nothing is
// held: the scanning happens after the response has been forwarded.

import { findings, log, settings, type Flow, type Hooks } from "reproxy";
import { BANNERS, disclosures, type Disclosure } from "./src/disclosures";

/** The disclosures recorded this run, keyed by value and host, so one is
 *  recorded once per host rather than once per response. */
const seen = new Set<string>();

/** Module state is per run, so it is cleared when the plugin loads. */
export function load(): void {
  seen.clear();
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
}

function draft(flow: Flow, d: Disclosure) {
  return {
    value: d.value,
    types: ["disclosure"],
    // The same on every host, so sightings merge into one finding.
    notes: `${d.label}, in the ${d.key} response header. ${d.note}`,
    fields: { detector: d.detector, header: d.key, ...(d.fields ?? {}) },
    flowId: flow.id,
    location: "response_header" as const,
    detail: d.key,
    // A disclosure is something to hide from an attacker, not from the
    // tester's screen, so it is never recorded hidden.
    hidden: false,
  };
}
