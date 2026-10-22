// Generating the variants a run tries, one per technique.
//
// A variant is the request the tester picked with a single mutation applied:
// a mutated path, an injected header, a URL-override header, a changed method,
// or the same request sent as HTTP/1.0. Each is a plain descriptor — a
// technique, a human-readable detail for the finding, and a Mutation that
// src/probe.ts turns into the request to send. Nothing here sends anything,
// so it is all testable with plain strings.
//
// The payloads come from path-payloads.json and header-payloads.json (the
// originals from PortSwigger's 403-bypasser), extended by the user's
// settings. The path technique also adds the well-known structural tricks
// (trailing slash, doubled slashes, /..;/, case changes, suffixes) that the
// payload list doesn't cover.

/** The five techniques a run can use. */
export type Technique = "path" | "header" | "override" | "method" | "downgrade";

/** One mutation to apply to the picked request. */
export interface Mutation {
  /** The URL the probe goes to: the original, a mutated path, or the
   *  override base path. */
  url: string;
  /** The method, when the technique changes it. */
  method?: string;
  /** Headers to add or override on the request. */
  headers?: [string, string][];
  /** Send as a raw HTTP/1.0 request rather than a structured one. */
  downgrade?: boolean;
  /** For a downgrade: strip the request to the start line and Host only. */
  strip?: boolean;
}

/** A variant: a technique, how to describe it, and the mutation to apply. */
export interface Variant {
  technique: Technique;
  detail: string;
  mutation: Mutation;
}

// A path technique can generate a lot of variants on a deep path; this caps
// what one call returns so generation stays bounded whatever the input. The
// run's request cap is the real limit on what is sent.
const MAX_PATH = 500;

// ---- URL helpers (exported; main and probe reuse them) ------------------------

export interface Parts {
  /** scheme://host[:port] */
  origin: string;
  /** The path, always starting with "/", without the query. */
  path: string;
  /** The query, without the leading "?" ("" when there is none). */
  query: string;
}

/** parts splits a URL into origin, path and query, dropping any fragment. */
export function parts(url: string): Parts {
  const s = url.indexOf("://");
  const scheme = s < 0 ? "" : url.slice(0, s + 3);
  let rest = s < 0 ? url : url.slice(s + 3);
  const hash = rest.indexOf("#");
  if (hash >= 0) rest = rest.slice(0, hash);
  const slash = rest.indexOf("/");
  const host = slash < 0 ? rest : rest.slice(0, slash);
  const tail = slash < 0 ? "/" : rest.slice(slash);
  const q = tail.indexOf("?");
  const path = q < 0 ? tail : tail.slice(0, q);
  const query = q < 0 ? "" : tail.slice(q + 1);
  return { origin: scheme + host, path: path || "/", query };
}

/** build reassembles a URL from an origin, a path and a query. */
export function build(origin: string, path: string, query: string): string {
  return origin + path + (query ? "?" + query : "");
}

/** pathOf returns a URL's path without the query, for messages and findings. */
export function pathOf(url: string): string {
  return parts(url).path;
}

/** requestTarget returns the origin-form request target (path and query)
 *  for a raw request line. */
export function requestTarget(url: string): string {
  const p = parts(url);
  return p.path + (p.query ? "?" + p.query : "");
}

/** hostOf returns the host[:port] of a URL. */
export function hostOf(url: string): string {
  const s = url.indexOf("://");
  let rest = s < 0 ? url : url.slice(s + 3);
  const slash = rest.indexOf("/");
  if (slash >= 0) rest = rest.slice(0, slash);
  const q = rest.indexOf("?");
  return q < 0 ? rest : rest.slice(0, q);
}

// ---- Path mutations -----------------------------------------------------------

interface PathMut {
  detail: string;
  path: string;
}

function ensureSlash(path: string): string {
  return path.endsWith("/") ? path : path + "/";
}

/** payloadMutations inserts each payload the way the original does: appended
 *  at the end, after the root, and around each internal slash. */
function payloadMutations(path: string, payloads: string[]): PathMut[] {
  const out: PathMut[] = [];
  const slashes: number[] = [];
  for (let i = 0; i < path.length; i++) if (path[i] === "/") slashes.push(i);

  for (const raw of payloads) {
    const p = String(raw).trim();
    if (!p) continue;
    out.push({ detail: `append "${p}"`, path: path + p });
    out.push({ detail: `append "/${p}"`, path: ensureSlash(path) + p });
    out.push({ detail: `append "/${p}/"`, path: ensureSlash(path) + p + "/" });
    out.push({ detail: `insert "${p}" after root`, path: "/" + p + path.slice(1) });
    for (const idx of slashes) {
      if (idx === 0) continue; // the leading slash is covered by "after root"
      out.push({ detail: `insert "${p}" after a segment`, path: path.slice(0, idx + 1) + p + path.slice(idx + 1) });
      out.push({ detail: `insert "${p}" before a slash`, path: path.slice(0, idx) + p + path.slice(idx) });
    }
  }
  return out;
}

/** structuralMutations adds the well-known path tricks that aren't single
 *  payloads: trailing/double slashes, dot-segments, case, and suffixes. */
function structuralMutations(path: string): PathMut[] {
  const out: PathMut[] = [];
  const stem = path.replace(/\/+$/, ""); // path without any trailing slashes
  out.push({ detail: "trailing slash", path: path + "/" });
  if (path.length > 1 && path.endsWith("/")) out.push({ detail: "no trailing slash", path: path.replace(/\/+$/, "") });
  out.push({ detail: "doubled slashes", path: path.replace(/\//g, "//") });
  out.push({ detail: 'append "/."', path: stem + "/." });
  out.push({ detail: 'append "/./"', path: stem + "/./" });
  out.push({ detail: 'append "/..;/"', path: stem + "/..;/" });
  out.push({ detail: "uppercase path", path: path.toUpperCase() });
  out.push({ detail: "lowercase path", path: path.toLowerCase() });

  const lastSlash = path.lastIndexOf("/");
  const seg = path.slice(lastSlash + 1);
  if (seg) {
    const swapped = seg
      .split("")
      .map((ch) => (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()))
      .join("");
    if (swapped !== seg) out.push({ detail: "swap-case last segment", path: path.slice(0, lastSlash + 1) + swapped });
  }
  for (const suf of [".json", ".html", ";.css"]) out.push({ detail: `suffix "${suf}"`, path: stem + suf });
  return out;
}

/** pathVariants builds the path technique's variants for a URL, de-duped by
 *  the resulting URL and excluding any that leave the path unchanged. */
export function pathVariants(url: string, payloads: string[]): Variant[] {
  const { origin, path, query } = parts(url);
  const muts = [...payloadMutations(path, payloads), ...structuralMutations(path)];
  const seen = new Set<string>();
  const out: Variant[] = [];
  for (const m of muts) {
    if (out.length >= MAX_PATH) break;
    if (m.path === path) continue; // no actual change
    const u = build(origin, m.path, query);
    if (seen.has(u)) continue;
    seen.add(u);
    out.push({ technique: "path", detail: m.detail, mutation: { url: u } });
  }
  return out;
}

// ---- Header injection ---------------------------------------------------------

/** headerVariants builds a variant per "Name: Value" line, injecting it on
 *  the original URL. A line with no value defaults to 127.0.0.1. */
export function headerVariants(url: string, lines: string[]): Variant[] {
  const out: Variant[] = [];
  const seen = new Set<string>();
  for (const raw of lines) {
    const line = String(raw).trim();
    if (!line) continue;
    const c = line.indexOf(":");
    const name = (c < 0 ? line : line.slice(0, c)).trim();
    const value = c < 0 ? "127.0.0.1" : line.slice(c + 1).trim();
    if (!name) continue;
    const key = name.toLowerCase() + ": " + value;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ technique: "header", detail: `${name}: ${value}`, mutation: { url, headers: [[name, value]] } });
  }
  return out;
}

// ---- URL-override headers ------------------------------------------------------

/** overrideVariants requests the permitted base path with the blocked path
 *  carried in an override header — the X-Original-URL / X-Rewrite-URL trick. */
export function overrideVariants(url: string, basePath: string, headers: string[]): Variant[] {
  const { origin, path, query } = parts(url);
  const target = path + (query ? "?" + query : "");
  const base = basePath.indexOf("/") === 0 ? basePath : "/" + basePath;
  const baseUrl = origin + base;
  const out: Variant[] = [];
  const seen = new Set<string>();
  for (const raw of headers) {
    const name = String(raw).trim();
    if (!name) continue;
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ technique: "override", detail: `${name}: ${target}`, mutation: { url: baseUrl, headers: [[name, target]] } });
  }
  return out;
}

/** overrideBaseUrl is the URL the override control request goes to: the
 *  permitted base path on the same origin, with nothing added. */
export function overrideBaseUrl(url: string, basePath: string): string {
  const { origin } = parts(url);
  const base = basePath.indexOf("/") === 0 ? basePath : "/" + basePath;
  return origin + base;
}

// ---- Method swaps -------------------------------------------------------------

/** methodVariants builds a variant per alternate method, skipping the
 *  request's own method. */
export function methodVariants(url: string, baseMethod: string, methods: string[]): Variant[] {
  const orig = baseMethod.toUpperCase();
  const out: Variant[] = [];
  const seen = new Set<string>();
  for (const raw of methods) {
    const m = String(raw).trim().toUpperCase();
    if (!m || m === orig || seen.has(m)) continue;
    seen.add(m);
    out.push({ technique: "method", detail: `${m} method`, mutation: { url, method: m } });
  }
  return out;
}

// ---- HTTP/1.0 downgrade -------------------------------------------------------

/** downgradeVariant builds the single HTTP/1.0 variant. */
export function downgradeVariant(url: string, method: string, strip: boolean): Variant {
  return { technique: "downgrade", detail: "HTTP/1.0 request", mutation: { url, method, downgrade: true, strip } };
}
