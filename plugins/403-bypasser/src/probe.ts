// Building one probe request from the request the user picked and a mutation.
//
// Everything the request carried is kept — the method, the body, and in
// particular the Cookie and Authorization headers — so a probe is sent as the
// same (blocked) user the tester is, not as an anonymous one: the question is
// whether that user can reach the resource by a trick. Hop-by-hop headers are
// dropped, and Host and Content-Length are set from the probe itself.
//
// Most mutations produce a structured request (a URL, method, headers and
// body). The HTTP/1.0 downgrade can't: the SDK's structured request is always
// written as HTTP/1.1, so the downgrade is built as a RawRequest whose bytes
// go to the wire verbatim, with the request line ending in HTTP/1.0.
//
// Every probe also carries a cache-buster — a query parameter unique to the
// run and the request — so an odd probe never shares a cache key with a real
// user, and the answer comes from the origin rather than a cached copy.

import type { RawRequest, Request } from "reproxy";
import { hostOf, requestTarget, type Mutation } from "./variants";

/** The parts of the chosen request a probe is built from. */
export interface Base {
  url: string;
  method: string;
  headers: [string, string][];
  body: string;
  contentType: string;
}

/** A name/value pair to add (the cache-buster). */
export interface Add {
  name: string;
  value: string;
}

// Headers never copied onto a probe: hop-by-hop headers belong to one
// connection, and Host and Content-Length are set from the probe itself.
const DROP = new Set([
  "host",
  "content-length",
  "connection",
  "keep-alive",
  "proxy-connection",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
]);

/** buildProbe makes the request for one variant, with the cache-buster added. */
export function buildProbe(base: Base, m: Mutation, cacheBuster?: Add): Request | RawRequest {
  const headers = base.headers.filter(([n]) => !DROP.has(n.toLowerCase()));
  if (m.headers) for (const h of m.headers) headers.push(h);
  const method = (m.method || base.method).toUpperCase();
  const url = cacheBuster ? withQuery(m.url, [cacheBuster]) : m.url;

  if (m.downgrade) {
    return rawRequest(url, method, m.strip ? [] : headers, base.body);
  }

  const req: Request = { url, method, headers };
  if (base.body !== "") req.body = base.body;
  return req;
}

/** rawRequest builds an HTTP/1.0 request as bytes, so the downgrade reaches
 *  the wire as HTTP/1.0 rather than the HTTP/1.1 the structured form forces. */
function rawRequest(url: string, method: string, headers: [string, string][], body: string): RawRequest {
  const lines = [`${method} ${requestTarget(url)} HTTP/1.0`, `Host: ${hostOf(url)}`];
  for (const [n, v] of headers) lines.push(`${n}: ${v}`);
  if (body !== "") lines.push(`Content-Length: ${utf8Len(body)}`);
  return { url, raw: lines.join("\r\n") + "\r\n\r\n" + body };
}

/** withQuery appends name=value pairs to a URL's query, keeping what was
 *  there and leaving any fragment in place. */
export function withQuery(url: string, adds: Add[]): string {
  if (adds.length === 0) return url;
  const hash = url.indexOf("#");
  const frag = hash >= 0 ? url.slice(hash) : "";
  const stem = hash >= 0 ? url.slice(0, hash) : url;
  const sep = stem.indexOf("?") >= 0 ? (stem.endsWith("?") || stem.endsWith("&") ? "" : "&") : "?";
  const added = adds.map((a) => `${enc(a.name)}=${enc(a.value)}`).join("&");
  return stem + sep + added + frag;
}

/** utf8Len is the byte length of a string, for a raw request's Content-Length. */
function utf8Len(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      n += 4; // a surrogate pair is one 4-byte code point
      i++;
    } else n += 3;
  }
  return n;
}

function enc(s: string): string {
  return encodeURIComponent(s);
}
