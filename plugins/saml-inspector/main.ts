// saml-inspector: decodes SAML exchanges and records what a tester should
// review.
//
// SAML travels in a few shapes: a browser POST with SAMLResponse/SAMLRequest
// form fields (base64, sometimes the whole assertion), a redirect with a
// ?SAMLRequest= query parameter (base64 + raw-DEFLATE), and raw XML in SOAP
// or ECP. This plugin finds those, decodes them, and reads the assertion:
// who it is about (the Subject/NameID), what it carries (attributes), how
// long it is good for (Conditions), and whether it is signed. Each concern
// becomes a finding linked to the request, so the tester can judge it.

import { findings, settings, log, type Flow, type Hooks, type Location, type Message } from "reproxy";
import { findSamlBlobs, decodeSaml, type SamlBlob } from "./src/decode";
import { inspect, type Concern } from "./src/inspect";

export async function scanRequest({ flow }: Hooks["traffic.on_request_forwarded"]): Promise<void> {
  // SAML in requests: the form POST back to the SP, or a redirect's query.
  await scan(flow, "request", flow.request, flow.url + " " + bodyText(flow.request));
}

export async function scanResponse({ flow }: Hooks["traffic.on_response_received"]): Promise<void> {
  // SAML in responses: the auto-submitting POST form the IdP returns.
  await scan(flow, "response", flow.response, bodyText(flow.response));
}

function bodyText(msg: Message): string {
  return msg.empty ? "" : msg.text();
}

async function scan(flow: Flow, side: "request" | "response", msg: Message, haystack: string): Promise<void> {
  const blobs = findSamlBlobs(flow.url, haystack);
  if (blobs.length === 0) return;
  const location = `${side}_body` as Location;
  const opts = {
    flagAttributes: settings.get<boolean>("flag_attributes"),
    flagWeaknesses: settings.get<boolean>("flag_weaknesses"),
    maxAgeHours: settings.get<number>("max_assertion_age_hours"),
    sensitive: settings.get<string[]>("sensitive_attributes").map((s) => s.toLowerCase()),
  };
  for (const blob of blobs) {
    const xml = decodeSaml(blob);
    if (!xml) continue;
    log.debug(`decoded ${blob.kind} (${xml.length} bytes) from ${flow.method} ${flow.url}`);
    for (const c of inspect(xml, blob, opts)) {
      await findings.record(draft(flow, location, c));
    }
  }
}

function draft(flow: Flow, location: Location, c: Concern) {
  return {
    value: c.value,
    types: [c.type],
    notes: `${c.title} in a SAML ${c.container} (${flow.method} ${flow.url}). ${c.detail}`,
    fields: c.fields,
    flowId: flow.id,
    location,
    detail: c.where,
  };
}
