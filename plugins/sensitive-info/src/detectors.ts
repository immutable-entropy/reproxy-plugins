// What counts as sensitive, and how a message is searched for it.
//
// A message is read in three parts — the query string of its URL, where a
// credential is a finding in itself, its headers, and its body — and each
// is searched by composed RE2 patterns that run in Go through text.scan
// (see pattern.ts). The head and the query are small, so all of the
// patterns are run over all of them.
//
// A body is not small, and Go's regexp has no literal to jump between when
// a pattern is a large alternation: measured on a 512 KiB body, the
// patterns for named fields alone cost over half a second, which no plugin
// may spend. So the body is scanned in two ways:
//
//   - A format with a literal in it (AKIA, -----BEGIN, $2y$, "password")
//     is anchored: one indexOf over a lower-cased copy says whether the
//     literal is in the body at all — 50 of those over 512 KiB cost about
//     7 ms — and the patterns are then run only on the windows of text
//     around the places it was found. The work is bounded by the window
//     budget rather than by the size of the body.
//   - A format with nothing to anchor on (a card number, an SSN) has to be
//     looked for everywhere, so those patterns — all of
//     them small — are run over the body up to a smaller limit of their
//     own (Options.maxPii).
//
// What this costs is covered by a test (test/cost.test.ts), which is the
// thing to re-run after touching a pattern.

import { log } from "reproxy";
import { classify, FIELD_ANCHORS, FIELD_BRANCHES } from "./fields";
import {
  branches,
  byId,
  HASH_RULES,
  HEADER_RULES,
  HEX_HASH_RULE,
  isSecret,
  KEY_RULES,
  PII_RULES,
  type FindingType,
  type Rule,
} from "./formats";
import { decodeClaims } from "./jwt";
import { compose, scan as scanPattern, type Composed, type Found } from "./pattern";
import { decodeBase64, digits, isPlaceholder, luhn, plausibleSsn, validIban } from "./validate";

export interface Options {
  /** The detectors (ids) or categories (finding types) to run; empty: all. */
  detectors: string[];
  /** Detectors or categories never to run. */
  skip: string[];
  minEntropy: number;
  /** The most of a body that is read at all. */
  maxBody: number;
  /** The most of a body the patterns that can't be anchored are run over. */
  maxPii: number;
  /** Report a token or session id in a header, which is the tester's own
   *  (see OWN_SESSION). */
  headerTokens: boolean;
  ignoreValues: string[];
  hexHashes: boolean;
  /** The most hits one message may yield. */
  maxHits: number;
}

/**
 * Detectors whose hits, when they are in a header, only describe the
 * session the tester is holding.
 *
 * This plugin runs beside a tester driving the application in a browser,
 * not beside an attacker on the wire: every Cookie, Set-Cookie,
 * Authorization and X-CSRF-Token that passes carries their own session,
 * and reporting it buries the findings that matter. So in a header a
 * value is only reported when something other than its field name shows
 * it to be a secret — a provider's key format (AKIA…, sk_live_…), a
 * password hash, a password or card number in clear, a Basic credential.
 * A token, a session id or a key-shaped value under a credential-sounding
 * header name is not: it is ours.
 *
 * The same value in a query string, a body or a recovered file is still
 * reported, because there it is the application putting it somewhere it
 * does not belong. The "header_session_tokens" setting turns the whole
 * policy off for anyone reading traffic that isn't their own.
 */
const OWN_SESSION = ["field_token", "field_session", "field_api_key", "field_username", "jwt", "hex_hash"];

/** Where in a message something was found. */
export type Where = "header" | "query" | "body";

export interface Hit {
  detector: string;
  label: string;
  type: FindingType;
  /** The secret itself: a finding's identity. */
  value: string;
  /** The field it was in, if it was in one. */
  key: string;
  where: Where;
  /** True when the value is a secret in itself, so it is recorded hidden. */
  secret: boolean;
  /** What the finding's notes should add about the risk. */
  note?: string;
  /** Extra detail for the finding, such as a JWT's claims. */
  fields?: Record<string, string>;
}

/** One side of an exchange, as scan reads it. */
export interface Input {
  side: "request" | "response";
  /** The start line and headers. */
  head?: string;
  /** The query string of the request's URL, without the "?". */
  query?: string;
  body?: string;
}

/** The field detectors, which have no rule of their own: their names and
 *  checks are in fields.ts, and this is what the catalog and the settings
 *  call them. */
const FIELD_DETECTORS: { id: string; label: string; category: FindingType }[] = [
  { id: "field_hash", label: "Password hash (named field)", category: "hash" },
  { id: "field_salt", label: "Password salt", category: "hash" },
  { id: "field_password", label: "Password", category: "credential" },
  { id: "field_pin", label: "One-time or PIN code", category: "credential" },
  { id: "field_api_key", label: "API key or secret", category: "secret-key" },
  { id: "field_token", label: "Token", category: "token" },
  { id: "field_session", label: "Session identifier", category: "token" },
  { id: "field_card", label: "Payment card number", category: "payment-data" },
  { id: "field_cvv", label: "Card security code", category: "payment-data" },
  { id: "field_bank", label: "Bank account detail", category: "payment-data" },
  { id: "field_gov_id", label: "Government identifier", category: "personal-data" },
  { id: "field_dob", label: "Date of birth", category: "personal-data" },
  { id: "field_username", label: "User name", category: "credential" },
];

/** Every detector's id, with the category (finding type) it belongs to. */
export const CATALOG: { id: string; label: string; category: FindingType }[] = [
  ...[...KEY_RULES, ...HASH_RULES, HEX_HASH_RULE, ...PII_RULES, ...HEADER_RULES].map((r) => ({
    id: r.id,
    label: r.label,
    category: r.type,
  })),
  ...FIELD_DETECTORS,
];

/** enabled reports whether a detector runs, by its id or its category. */
export function enabled(opts: Options, id: string, category: FindingType): boolean {
  if (opts.skip.indexOf(id) >= 0 || opts.skip.indexOf(category) >= 0) return false;
  if (opts.detectors.length === 0) return true;
  return opts.detectors.indexOf(id) >= 0 || opts.detectors.indexOf(category) >= 0;
}

// The window budget: how much text around an anchor is scanned, how many
// windows a body may yield, and how much they may come to in all. A body
// with more candidates than this is sampled rather than read whole, which
// is said in the log.
const WINDOW_BEFORE = 80;
const WINDOW_AFTER = 352;
const MAX_WINDOWS = 48;
const MAX_WINDOW_BYTES = 32 * 1024;
const MAX_PER_ANCHOR = 8;

// Windows are joined with a separator no pattern can match through, so one
// scan covers all of them.
const SEP = "\n\u0000\n";

/** A literal to look for, and how much text around it to scan. */
interface Needle {
  text: string;
  before: number;
  after: number;
}

// The composed patterns and needles, rebuilt only when the settings that
// shape them change. Composing is cheap, but a message is not the place to
// do it.
interface Sets {
  /** The formats with a literal to anchor on. */
  anchored: Composed;
  /** The formats with nothing to anchor on. */
  unanchored: Composed;
  fields: Composed;
  headers: Composed;
  needles: Needle[];
  rules: Record<string, Rule>;
}
let cache: { sig: string; sets: Sets } | null = null;

/** reset drops what is cached between runs (see plugin.on_load). */
export function reset(): void {
  cache = null;
}

function sets(opts: Options): Sets {
  const sig = `${opts.detectors.join(",")}|${opts.skip.join(",")}|${opts.hexHashes}`;
  if (cache && cache.sig === sig) return cache.sets;

  const keep = (rules: Rule[]) => rules.filter((r) => enabled(opts, r.id, r.type));
  const formats = keep([...KEY_RULES, ...HASH_RULES]);
  if (opts.hexHashes && enabled(opts, HEX_HASH_RULE.id, HEX_HASH_RULE.type)) {
    formats.push(HEX_HASH_RULE);
  }
  const anchored = formats.filter((r) => r.anchors && r.anchors.length > 0);
  const unanchored = formats.filter((r) => !r.anchors || r.anchors.length === 0).concat(keep(PII_RULES));

  const built: Sets = {
    anchored: compose("anchored", branches(anchored)),
    unanchored: compose("unanchored", branches(unanchored)),
    fields: compose("fields", FIELD_BRANCHES),
    headers: compose("headers", branches(keep(HEADER_RULES))),
    needles: needlesOf(anchored),
    rules: byId([...KEY_RULES, ...HASH_RULES, HEX_HASH_RULE, ...PII_RULES, ...HEADER_RULES]),
  };
  cache = { sig, sets: built };
  return built;
}

/** needlesOf gathers what to look for in a body: every anchored rule's
 *  literals, and the names a field detector could be called by. */
function needlesOf(anchored: Rule[]): Needle[] {
  const byText: Record<string, Needle> = {};
  const want = (text: string, before: number, after: number) => {
    const n = byText[text];
    if (!n) {
      byText[text] = { text, before, after };
      return;
    }
    n.before = Math.max(n.before, before);
    n.after = Math.max(n.after, after);
  };
  for (const r of anchored) {
    for (const a of r.anchors ?? []) {
      want(a, r.before ?? WINDOW_BEFORE, r.after ?? WINDOW_AFTER);
    }
  }
  for (const a of FIELD_ANCHORS) {
    want(a, WINDOW_BEFORE, WINDOW_AFTER);
  }
  const out: Needle[] = [];
  for (const text in byText) out.push(byText[text]);
  return out;
}

/**
 * scan finds the sensitive values in one side of an exchange. Nothing it
 * returns needs decoding or checking again: a hit is something to report.
 */
export function scan(input: Input, opts: Options): Hit[] {
  const s = sets(opts);
  const hits: Pending[] = [];
  const seen: Record<string, boolean> = {};
  const max = Math.min(200, Math.max(8, opts.maxHits * 4));
  let credential = false;

  const add = (hit: Pending | null): void => {
    if (!hit || hits.length >= opts.maxHits) return;
    // A window's own end, where the text of the next one begins.
    const cut = hit.value.indexOf("\u0000");
    if (cut >= 0) hit.value = hit.value.slice(0, cut).trim();
    if (!hit.value || !enabled(opts, hit.detector, hit.type) || ignored(hit.value, opts)) return;
    if (hit.where === "header" && !opts.headerTokens && OWN_SESSION.indexOf(hit.detector) >= 0) return;
    if (seen[hit.value]) return;
    seen[hit.value] = true;
    // A user name is not what makes a message a login: only something it
    // can be paired with counts.
    if (!hit.pending && (hit.type === "credential" || hit.type === "secret-key" || hit.type === "hash")) {
      credential = true;
    }
    hits.push(hit);
  };

  // The query comes first because the request line repeats it inside the
  // head: taking the query's own part first is what makes a credential in
  // the URL read as one, rather than as something in the headers.
  if (input.query) readAll(s, input.query, "query", max, opts, add);
  if (input.head) {
    for (const m of scanPattern(s.headers, input.head, max)) add(fromHeader(m, s.rules));
    readAll(s, input.head, "header", max, opts, add);
  }
  if (input.body && hits.length < opts.maxHits) readBody(s, input.body, max, opts, add);

  // A user name is only a login beside the password it was sent with, and
  // only in a request: a response that echoes "username" is not a leak.
  return hits.filter((h) => !h.pending || (credential && input.side === "request")).map(strip);
}

/** readAll runs every pattern over a part small enough for that: a head, a
 *  query string, a WebSocket message. */
function readAll(s: Sets, text: string, where: Where, max: number, opts: Options, add: (h: Pending | null) => void): void {
  for (const m of scanPattern(s.anchored, text, max)) add(fromFormat(m, s.rules, where, opts));
  for (const m of scanPattern(s.unanchored, text, max)) add(fromFormat(m, s.rules, where, opts));
  for (const m of scanPattern(s.fields, text, max)) add(fromField(m, where, opts));
}

/** readBody scans a body the affordable way: the anchored patterns around
 *  the literals they need, the rest over as much of the body as the
 *  unanchored limit allows. */
function readBody(s: Sets, body: string, max: number, opts: Options, add: (h: Pending | null) => void): void {
  const text = body.length > opts.maxBody ? body.slice(0, opts.maxBody) : body;
  const found = windows(text.toLowerCase(), s.needles);
  if (found.ranges.length > 0) {
    const parts: string[] = [];
    for (const r of found.ranges) parts.push(text.slice(r[0], r[1]));
    const joined = parts.join(SEP);
    for (const m of scanPattern(s.anchored, joined, max)) add(fromFormat(m, s.rules, "body", opts));
    for (const m of scanPattern(s.fields, joined, max)) add(fromField(m, "body", opts));
  }
  if (found.sampled) {
    log.debug(
      `a body of ${Math.round(text.length / 1024)} KiB held more candidates than the window budget: ` +
        `${MAX_WINDOWS} places were read`,
    );
  }
  const pii = text.length > opts.maxPii ? text.slice(0, opts.maxPii) : text;
  for (const m of scanPattern(s.unanchored, pii, max)) add(fromFormat(m, s.rules, "body", opts));
}

/** windows finds where in a (lower-cased) body the anchored patterns could
 *  match, as merged ranges within the window budget. */
export function windows(lower: string, needles: Needle[]): { ranges: [number, number][]; sampled: boolean } {
  const raw: [number, number][] = [];
  let sampled = false;
  for (const n of needles) {
    let from = 0;
    for (let i = 0; i < MAX_PER_ANCHOR; i++) {
      const at = lower.indexOf(n.text, from);
      if (at < 0) break;
      raw.push([Math.max(0, at - n.before), Math.min(lower.length, at + n.text.length + n.after)]);
      from = at + n.text.length;
      if (i === MAX_PER_ANCHOR - 1 && lower.indexOf(n.text, from) >= 0) sampled = true;
    }
  }
  if (raw.length === 0) return { ranges: [], sampled };
  raw.sort((a, b) => a[0] - b[0]);

  const ranges: [number, number][] = [];
  let bytes = 0;
  for (const r of raw) {
    const last = ranges.length > 0 ? ranges[ranges.length - 1] : null;
    if (last && r[0] <= last[1]) {
      if (r[1] > last[1]) {
        bytes += r[1] - last[1];
        last[1] = r[1];
      }
      continue;
    }
    if (ranges.length >= MAX_WINDOWS || bytes + (r[1] - r[0]) > MAX_WINDOW_BYTES) {
      sampled = true;
      break;
    }
    ranges.push([r[0], r[1]]);
    bytes += r[1] - r[0];
  }
  return { ranges, sampled };
}

// pending marks a hit held back until the message turns out to hold a
// credential too. It is dropped from what scan returns.
interface Pending extends Hit {
  pending?: boolean;
}

function strip(h: Pending): Hit {
  const out: Hit = {
    detector: h.detector,
    label: h.label,
    type: h.type,
    value: h.value,
    key: h.key,
    where: h.where,
    secret: isSecret(h.type, h.detector),
  };
  if (h.note) out.note = h.note;
  if (h.fields) out.fields = h.fields;
  return out;
}

function ignored(value: string, opts: Options): boolean {
  if (isPlaceholder(value)) return true;
  for (const v of opts.ignoreValues) {
    if (v && value.toLowerCase() === v.toLowerCase()) return true;
  }
  return false;
}

/**
 * fromHeader reads an Authorization line. Only Basic reaches here (see
 * HEADER_RULES), and it is decoded to the user and password it hides.
 */
function fromHeader(m: Found, rules: Record<string, Rule>): Pending | null {
  const value = (m.groups[0] ?? "").trim();
  if (!value) return null;
  const plain = decodeBase64(value);
  if (!plain || plain.indexOf(":") <= 0) return null;
  return {
    detector: m.id,
    label: rules[m.id].label,
    type: "credential",
    value: plain,
    key: "Authorization",
    where: "header",
    secret: true,
    fields: { user: plain.slice(0, plain.indexOf(":")) },
    note: "Basic authentication is the password itself, base64 encoded, on every request.",
  };
}

/** fromFormat turns a match of a shape-based rule into a hit, checking what
 *  the shape alone can't tell (a card's check digit, an IBAN's checksum). */
function fromFormat(m: Found, rules: Record<string, Rule>, where: Where, opts: Options): Pending | null {
  const rule = rules[m.id];
  if (!rule) return null;
  let value = m.match.trim();
  switch (m.id) {
    case "credit_card":
      if (!luhn(value)) return null;
      break;
    case "ssn":
      if (!plausibleSsn(value)) return null;
      break;
    case "iban":
      if (!validIban(value)) return null;
      break;
    case "uk_nino":
      // A chance run of letters and digits inside a token looks like one.
      if (digits(value).length !== 6) return null;
      break;
    case "private_key":
      // A key is its own identity, but a finding needn't carry pages of it.
      if (value.length > 4096) value = value.slice(0, 4096) + "…";
      break;
    case "azure_storage_key":
      value = value.slice(value.indexOf("=") + 1);
      break;
  }
  const hit: Pending = { detector: m.id, label: rule.label, type: rule.type, value, key: "", where, secret: true };
  if (rule.note) hit.note = rule.note;
  if (m.id === "jwt") {
    const claims = decodeClaims(value);
    if (claims) hit.fields = claims;
  }
  return hit;
}

/** fromField turns a "name = value" match into a hit, if the name means
 *  anything and the value holds something. */
function fromField(m: Found, where: Where, opts: Options): Pending | null {
  const name = m.groups[0] ?? "";
  const value = m.groups[1] ?? "";
  if (!name || !value) return null;
  const field = classify(name, value, opts.minEntropy);
  if (!field) return null;
  const hit: Pending = {
    detector: field.id,
    label: field.label,
    type: field.type,
    value: field.value,
    key: name.replace(/^["']|["']$/g, ""),
    where,
    secret: true,
  };
  if (field.note) hit.note = field.note;
  if (field.needsCredential) hit.pending = true;
  return hit;
}
