// footprint: maps an organisation's external footprint from its own traffic.
//
// Each in-scope response is read as it arrives (traffic.on_response_received).
// Three things are gathered from it, all after the response has been
// forwarded, so nothing is held:
//
//   - the http(s) URLs it refers to (text.urls, which runs in Go) are each
//     classified (src/links.ts) as a social-media account, a source-code
//     repository, a cloud bucket, a package-registry entry or an API/docs
//     endpoint;
//   - everything that isn't an ordinary link — third-party service ids,
//     mailto:/tel: links, s3:// URIs, structured postal addresses, and email
//     and telephone text — is found by anchored patterns (src/patterns.ts);
//   - a social or source link is judged by where it sits in the markup
//     (src/context.ts): one in the header, footer or nav, or carrying
//     rel="me", is the organisation's own; one in the page content may be a
//     third party's.
//
// Links to individual posts and repository files are left out by default
// (the "include_content_links" setting), so what is recorded is the accounts
// and repositories themselves, not every share button and deep link.
//
// This is the footprint half of the old "sensitive-info" plugin: contact
// details and the external presence. Secrets and highly sensitive personal
// data stay with "sensitive-info"; stack-disclosure headers are the
// "stack-disclosure" plugin's. It only reads responses and records findings;
// it holds, changes and sends nothing.

import { findings, settings, text, type Flow, type Hooks, type Message } from "reproxy";
import { analyze, type Context } from "./src/context";
import { classify, type FindingType, type Hit } from "./src/links";
import { scan as scanPatterns } from "./src/patterns";

export async function scanResponse({ flow }: Hooks["traffic.on_response_received"]): Promise<void> {
  const maxBody = num("max_body_kb", 512) * 1024;
  const body = readBody(flow.response, maxBody);
  if (!body) return;

  const skip = settings.get<string[]>("skip_detectors") ?? [];
  const includeContent = settings.get<boolean>("include_content_links") === true;
  const maxHits = Math.max(1, num("max_findings", 50));
  const lower = body.toLowerCase();

  const hits: { hit: Hit; ctx?: Context }[] = [];
  const seen = new Set<string>();
  const take = (hit: Hit, ctx?: Context): void => {
    if (enabled(skip, hit) === false) return;
    const key = `${hit.type}\u0000${hit.value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    hits.push({ hit, ctx });
  };

  // Links the response refers to, resolved to absolute URLs in Go.
  const urls = text.urls(body, flow.url, contentType(flow.response), 500);
  for (const url of urls) {
    const hit = classify(url);
    if (!hit) continue;
    if (hit.kind === "content" && !includeContent) continue;
    let ctx: Context | undefined;
    if (hit.type === "social-account" || hit.type === "source-repo") {
      // Look for the link where the markup actually wrote it: its host and
      // path, which survive a resolved or protocol-relative URL.
      ctx = analyze(lower, needle(url));
    }
    take(hit, ctx);
  }

  // Everything that isn't an ordinary link.
  for (const hit of scanPatterns(body, { maxPii: num("max_pii_kb", 128) * 1024, ignoreEmails: settings.get<string[]>("ignore_emails") ?? [], max: Math.min(500, maxHits * 4) })) {
    take(hit);
  }

  let recorded = 0;
  for (const { hit, ctx } of hits) {
    if (recorded >= maxHits) break;
    recorded++;
    await findings.record(draft(flow, hit, ctx));
  }
}

/** enabled reports whether a hit's detector and category are both allowed. */
function enabled(skip: string[], hit: Hit): boolean {
  return skip.indexOf(hit.detector) < 0 && skip.indexOf(hit.type) < 0;
}

/** needle is what to look for in the markup to place a link: its host and
 *  path, without the scheme, which a resolved absolute URL may have changed. */
function needle(url: string): string {
  const m = /^https?:\/\/([^#]*)/i.exec(url);
  return m ? m[1].toLowerCase().replace(/\/+$/, "") : "";
}

function draft(flow: Flow, hit: Hit, ctx?: Context) {
  return {
    value: hit.value,
    types: [hit.type as FindingType],
    notes: notesFor(hit, ctx),
    fields: {
      detector: hit.detector,
      ...(hit.fields ?? {}),
      ...(ctx ? { context: ctx.region, source: ctx.official ? "the site itself" : "page content" } : {}),
    },
    flowId: flow.id,
    location: "response_body" as const,
    detail: hit.label,
    // Footprint findings identify, they don't authenticate, so none is hidden.
    hidden: false,
  };
}

/** notesFor says what was found and, for a social or source link, how sure we
 *  are it is the organisation's own. It names nothing flow-specific, so every
 *  sighting merges into one finding whose links say where it was seen. */
function notesFor(hit: Hit, ctx?: Context): string {
  let n = `${hit.label}: ${hit.value}.`;
  if (ctx && (hit.type === "social-account" || hit.type === "source-repo")) {
    n += ctx.official
      ? ` Linked from the site's ${ctx.region === "body" ? "markup" : ctx.region}${ctx.relMe ? ' with rel="me"' : ""}, so it is very likely the organisation's own.`
      : " Linked from the page content, so it may belong to a third party or a visitor rather than the organisation.";
  }
  if (hit.note) n += " " + hit.note;
  return n;
}

/** readBody returns a response's text when it is textual and small enough. */
function readBody(msg: Message, maxBody: number): string {
  if (msg.empty || msg.size > maxBody) return "";
  const type = msg.contentType();
  if (type && !textual(type)) return "";
  return msg.text();
}

function contentType(msg: Message): string {
  return msg.contentType() ?? "";
}

/** textual is what is worth reading as text: markup, scripts and data. */
function textual(type: string): boolean {
  if (type.indexOf("text/") === 0) return true;
  return /^application\/(?:xhtml\+xml|json|.*\+json|javascript|x-javascript|ecmascript|xml|.*\+xml)/.test(type);
}

function num(key: string, dflt: number): number {
  const n = Number(settings.get<number>(key));
  return Number.isFinite(n) && n > 0 ? n : dflt;
}
