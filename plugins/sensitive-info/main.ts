// sensitive-info: flags credentials, tokens, keys and personal data in
// traffic as findings.
//
// Requests are scanned once sent (traffic.on_request_forwarded), responses
// as they arrive (traffic.on_response_received, text types only). Each hit
// becomes a finding whose value is the secret itself, linked to the request
// and to where in it the secret was; the same secret seen again just gains a
// sighting.

import { findings, log, settings, type Flow, type Hooks, type Location, type Message } from "reproxy";
import { scan, type Hit, type Options } from "./src/detectors";
import { redact } from "./src/redact";

export async function scanRequest({ flow }: Hooks["traffic.on_request_forwarded"]): Promise<void> {
  if (!settings.get<boolean>("scan_requests")) return;
  await record(flow, "request", flow.request);
}

export async function scanResponse({ flow }: Hooks["traffic.on_response_received"]): Promise<void> {
  await record(flow, "response", flow.response);
}

async function record(flow: Flow, side: "request" | "response", msg: Message): Promise<void> {
  if (msg.empty) return;
  const body = msg.size <= options().maxBody ? msg.text() : "";
  for (const hit of scan(msg.head(), body, side, options())) {
    log.debug(`${hit.detector} in flow ${flow.id}: ${redact(hit.value)}`);
    await findings.record(draft(flow, side, hit));
  }
}

function options(): Options {
  return {
    detectors: settings.get<string[]>("detectors"),
    minEntropy: settings.get<number>("min_entropy"),
    maxBody: settings.get<number>("max_body_kb") * 1024,
    ignoreEmails: settings.get<string[]>("ignore_emails"),
  };
}

function draft(flow: Flow, side: "request" | "response", hit: Hit) {
  const location = `${side}_${hit.inHeader ? "header" : "body"}` as Location;
  const where = hit.inHeader ? `the ${side} headers` : `the ${side} body`;
  return {
    value: hit.value,
    types: [hit.type],
    notes: `${hit.label} in ${where} of ${flow.method} ${flow.url}`,
    fields: { detector: hit.detector, ...(hit.key ? { key: hit.key } : {}), ...(hit.fields ?? {}) },
    flowId: flow.id,
    location,
    detail: hit.key || hit.detector,
  };
}
