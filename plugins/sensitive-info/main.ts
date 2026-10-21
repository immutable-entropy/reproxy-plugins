// sensitive-info: flags credentials, keys, tokens, hashes and personal data
// in traffic as findings.
//
// Requests are read once sent (traffic.on_request_forwarded), responses as
// they arrive (traffic.on_response_received), and WebSocket messages as
// they pass (websocket.on_message). Each side is searched in three parts:
// its headers, the query string of its URL — where a credential is a
// finding in itself, because the URL reaches logs and Referer headers — and
// its body. Replayed and agent traffic comes through the same hooks, so
// what the tester replays is scanned too.
//
// The files the work recovered are read as well (file.on_created, and
// file.on_batch_complete for a recovery too large for the queue). A secret
// embedded in the source another plugin un-webpacked out of an exposed map
// is in every copy of the application anyone downloads, which makes it the
// least arguable finding this plugin makes — and reading it needs no code
// beyond what a response body already needs.
//
// What this plugin does not report is the tester's own session. It runs
// beside somebody driving the application in a browser, not beside an
// attacker on the wire, so the Cookie, Set-Cookie, Authorization and
// X-CSRF-Token headers that pass carry credentials they already have. A
// token or session identifier in a header is therefore left alone, while
// what a format proves to be a secret — a provider's key, a password hash,
// a password or card number in clear, an HTTP Basic credential — is still
// reported wherever it turns up (see OWN_SESSION in src/detectors.ts).
//
// Every hit becomes a finding whose value is the secret itself, linked to
// the request it was seen in and to where in it the secret was; the same
// secret seen again just gains a sighting. A value that is a secret in
// itself is recorded hidden, so reProxy keeps it masked until the user
// clicks the eye beside it — an identifier that endangers (a Social Security
// or passport number) is masked, while a date of birth, which identifies but
// doesn't authenticate, is left readable. Nothing is held: the scanning
// happens after the message has been forwarded.
//
// This is the highly sensitive half of the old "sensitive-info" plugin:
// secrets and the personal data that is a serious finding in itself. Contact
// details (emails, telephone numbers, addresses) and the external footprint
// now belong to the "footprint" plugin, and what response headers give away
// about the stack to the "stack-disclosure" plugin.

import { files, findings, log, settings, type Flow, type Hooks, type Location, type Message, type RecoveredFile } from "reproxy";
import { reset, scan, type Hit, type Input, type Options, type Where } from "./src/detectors";
import { redact } from "./src/redact";

/** The recovered files already read this run, so neither hook reads one twice. */
const scanned = new Set<number>();

/** Module state is per run, so it is cleared when the plugin loads. */
export function load(): void {
  reset();
  scanned.clear();
}

export async function scanRequest({ flow }: Hooks["traffic.on_request_forwarded"]): Promise<void> {
  if (!settings.get<boolean>("scan_requests")) return;
  await record(flow, "request", { side: "request", head: flow.request.head(), query: flow.query, body: body(flow.request) });
}

export async function scanResponse({ flow }: Hooks["traffic.on_response_received"]): Promise<void> {
  await record(flow, "response", { side: "response", head: flow.response.head(), body: body(flow.response) });
}

export async function scanWebSocket({ flow, message }: Hooks["websocket.on_message"]): Promise<void> {
  if (message.type !== "text") return;
  const side = message.direction === "sent" ? "request" : "response";
  const text = message.size <= options().maxBody ? message.text() : "";
  await record(flow, side, { side, body: text }, `WebSocket message ${message.seq}`);
}

/**
 * scanFile reads a file the work recovered — the original source a plugin
 * un-webpacked out of a source map, a configuration file, anything else
 * put under the engagement. A secret in one of those is the application's
 * own, embedded in what it ships, rather than something passing through,
 * so it is the most objective finding this plugin makes.
 */
export async function scanFile({ file }: Hooks["file.on_created"]): Promise<void> {
  await readFile(file);
}

/**
 * scanBatch takes a whole recovery. Un-webpacking a build can write
 * thousands of files at once, far more than a plugin's queue holds, so the
 * batch is the event to work from: every file in it is read here, at this
 * plugin's own pace.
 */
export async function scanBatch({ batch }: Hooks["file.on_batch_complete"]): Promise<void> {
  if (settings.get<boolean>("scan_files") === false) return;
  const found = files.list({ batch: batch.id, textOnly: true, limit: 1000 });
  log.info(`reading ${found.length} of the ${batch.files} files recovered from ${batch.label || batch.id}`);
  if (batch.files > found.length) {
    log.warn(`${batch.files - found.length} files of that recovery were not read: only the newest 1000 of a recovery are`);
  }
  for (const file of found) await readFile(file);
}

async function readFile(file: RecoveredFile): Promise<void> {
  if (settings.get<boolean>("scan_files") === false) return;
  if (!file.text || scanned.has(file.id)) return;
  scanned.add(file.id);
  const opts = options();
  if (file.size > opts.maxBody) {
    log.debug(`${file.path} is larger than the body limit (${Math.round(file.size / 1024)} KiB), so it was not read`);
    return;
  }
  let text: string;
  try {
    text = (await files.read(file, opts.maxBody)).text;
  } catch (e) {
    log.debug(`couldn't read ${file.path}: ${String(e)}`);
    return;
  }
  const hits = scan({ side: "response", body: text }, opts);
  for (const hit of hits) {
    log.debug(`${hit.detector} in ${file.path}: ${redact(hit.value)}`);
    await findings.record(fileDraft(file, hit));
  }
  if (hits.length >= opts.maxHits) {
    log.info(`${file.path}: stopped at ${opts.maxHits} findings (see the "Most findings from one message" setting)`);
  }
}

function fileDraft(file: RecoveredFile, hit: Hit) {
  const from = file.url ? ` It was recovered from ${file.url}.` : file.host ? ` It was recovered from ${file.host}.` : "";
  let notes =
    `${hit.label} in ${file.path}, a file recovered from the work and kept under this engagement.${from} ` +
    `A secret in a file the application ships is in every copy of it, and is read by anyone who downloads it: ` +
    `it is not a value that happened to pass by.`;
  if (hit.key) notes += ` The field was named "${hit.key}".`;
  if (hit.note) notes += ` ${hit.note}`;
  return {
    value: hit.value,
    types: [hit.type],
    notes,
    fields: {
      detector: hit.detector,
      where: "recovered file",
      file: file.path,
      ...(hit.key ? { field: hit.key } : {}),
      ...(hit.fields ?? {}),
    },
    flowId: file.flowId || undefined,
    location: file.flowId ? ("response_body" as Location) : undefined,
    detail: file.path,
    hidden: hit.secret && settings.get<boolean>("hide_secrets"),
    files: [file.id],
  };
}

async function record(flow: Flow, side: "request" | "response", input: Input, what = ""): Promise<void> {
  const opts = options();
  const hits = scan(input, opts);
  if (hits.length === 0) return;
  for (const hit of hits) {
    log.debug(`${hit.detector} in flow ${flow.id}: ${redact(hit.value)}`);
    await findings.record(draft(flow, side, hit, what));
  }
  if (hits.length >= opts.maxHits) {
    log.info(`flow ${flow.id}: stopped at ${opts.maxHits} findings (see the "Most findings from one message" setting)`);
  }
}

/** body is a message's text, when it is text and small enough to read. The
 *  content type is checked first, so a large upload is never decoded. */
function body(msg: Message): string {
  if (msg.empty || msg.size > options().maxBody) return "";
  const type = msg.contentType();
  if (type && !textual(type)) return "";
  return msg.text();
}

// What is worth reading as text. Anything else (an image, a font, an
// archive) can only waste the time it takes to decode it.
function textual(type: string): boolean {
  if (type.indexOf("text/") === 0) return true;
  return /^application\/(?:json|.*\+json|x-ndjson|javascript|x-javascript|ecmascript|xml|.*\+xml|x-www-form-urlencoded|graphql.*|x-amz-json.*|csv|yaml|x-yaml|sql|x-sh)$/.test(type) || type.indexOf("multipart/") === 0;
}

function options(): Options {
  return {
    detectors: settings.get<string[]>("detectors"),
    skip: settings.get<string[]>("skip_detectors"),
    minEntropy: settings.get<number>("min_entropy"),
    maxBody: settings.get<number>("max_body_kb") * 1024,
    maxPii: settings.get<number>("max_pii_kb") * 1024,
    ignoreValues: settings.get<string[]>("ignore_values"),
    hexHashes: settings.get<boolean>("hex_hashes"),
    headerTokens: settings.get<boolean>("header_session_tokens") === true,
    maxHits: settings.get<number>("max_findings"),
  };
}

function draft(flow: Flow, side: "request" | "response", hit: Hit, what: string) {
  const location = `${side}_${hit.where === "body" ? "body" : "header"}` as Location;
  return {
    value: hit.value,
    types: [hit.type],
    notes: notes(flow, side, hit, what),
    fields: {
      detector: hit.detector,
      where: `${side} ${hit.where}`,
      ...(hit.key ? { field: hit.key } : {}),
      ...(hit.fields ?? {}),
    },
    flowId: flow.id,
    location,
    detail: hit.key || (what ? what : hit.detector),
    hidden: hit.secret && settings.get<boolean>("hide_secrets"),
  };
}

/** notes says what was found, where, and why it matters. */
function notes(flow: Flow, side: "request" | "response", hit: Hit, what: string): string {
  const place = what || `the ${side} ${where(hit.where)}`;
  let text = `${hit.label} in ${place} of ${flow.method} ${flow.url}.`;
  if (hit.key) text += ` The field was named "${hit.key}".`;
  if (hit.where === "query") {
    text += " A value in the query string is kept in server and proxy logs, in browser history, and is sent on in Referer headers.";
  }
  if (hit.note) text += ` ${hit.note}`;
  return text;
}

function where(w: Where): string {
  switch (w) {
    case "header":
      return "headers";
    case "query":
      return "URL query string";
    default:
      return "body";
  }
}
