// Building one probe request from the request the user picked.
//
// A probe is the original request with some guessed inputs added — query
// parameters, headers, body fields or cookies — each carrying its own
// canary value. Everything else is kept: the method, the path, the body,
// and the Cookie and Authorization headers, so the probe is made as the
// same user the tester is, not as an anonymous one.
//
// Every probe also carries a cache-buster: a query parameter with a name
// unique to this run and a value unique to this request. Behind a CDN or a
// load balancer that is what keeps a probe from sharing a cache key with a
// real user — so a guessed header can be tested for its effect on the
// response without that response being stored and served to anyone else.
// It is also why a probe's answer comes from the origin and not from a
// cached copy that would hide what the guess did.

import type { Candidate, Location } from "./detect";

/** The parts of the chosen request a probe is built from. */
export interface Base {
  url: string;
  method: string;
  /** The request's headers, as name/value pairs. */
  headers: [string, string][];
  /** The request body, as text ("" when there is none). */
  body: string;
  /** The request's Content-Type, lower-cased, for body injection. */
  contentType: string;
}

/** A name/value pair to add. */
export interface Add {
  name: string;
  value: string;
}

/** What http.send is handed: a URL, method, headers and body. */
export interface Probe {
  url: string;
  method: string;
  headers: [string, string][];
  body?: string;
}

// Headers never sent as guesses or copied onto a probe: hop-by-hop headers
// belong to one connection, and Host and Content-Length are set from the
// probe itself.
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

/**
 * buildProbe makes the request for one batch of guesses at one location.
 * cacheBuster is added to the query of every probe, whatever the location.
 */
export function buildProbe(base: Base, location: Location, adds: Add[], cacheBuster: Add): Probe {
  const headers = base.headers.filter(([n]) => !DROP.has(n.toLowerCase()));
  const queryAdds: Add[] = [cacheBuster];
  let body = base.body;

  switch (location) {
    case "query":
      for (const a of adds) queryAdds.push(a);
      break;
    case "header":
      for (const a of adds) headers.push([a.name, a.value]);
      break;
    case "cookie":
      addCookies(headers, adds);
      break;
    case "body":
      body = addToBody(base, adds);
      break;
  }

  const probe: Probe = {
    url: withQuery(base.url, queryAdds),
    method: base.method,
    headers,
  };
  if (base.body !== "" || location === "body") probe.body = body;
  return probe;
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

function addCookies(headers: [string, string][], adds: Add[]): void {
  const pairs = adds.map((a) => `${a.name}=${a.value}`).join("; ");
  const at = headers.findIndex(([n]) => n.toLowerCase() === "cookie");
  if (at >= 0) headers[at] = [headers[at][0], `${headers[at][1]}; ${pairs}`];
  else headers.push(["Cookie", pairs]);
}

/**
 * addToBody adds fields to the request body in the form the body already
 * uses: keys in a JSON object, pairs in a form. A body of a kind this can't
 * extend (or no body at all) is left as it is — the caller leaves that
 * location out of the run when it can't be mined.
 */
export function addToBody(base: Base, adds: Add[]): string {
  const type = base.contentType;
  if (type.indexOf("application/json") >= 0 || type.indexOf("+json") >= 0) {
    const obj = parseObject(base.body);
    if (obj) {
      for (const a of adds) if (!(a.name in obj)) obj[a.name] = a.value;
      return JSON.stringify(obj);
    }
    return base.body;
  }
  // Treat everything else as form-encoded, the other body params travel in.
  const added = adds.map((a) => `${enc(a.name)}=${enc(a.value)}`).join("&");
  if (base.body.trim() === "") return added;
  return base.body + "&" + added;
}

/** canBody reports whether a request's body is one fields can be added to. */
export function canBody(base: Base): boolean {
  const type = base.contentType;
  if (type.indexOf("application/json") >= 0 || type.indexOf("+json") >= 0) return parseObject(base.body) !== undefined;
  if (type.indexOf("application/x-www-form-urlencoded") >= 0) return true;
  // A request with a form-ish body but no declared type is still minable.
  return base.body.trim() !== "" && base.body.indexOf("=") >= 0 && base.contentType === "";
}

function parseObject(body: string): Record<string, unknown> | undefined {
  try {
    const v = JSON.parse(body);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function enc(s: string): string {
  return encodeURIComponent(s);
}
