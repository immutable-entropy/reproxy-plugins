// The names to guess, per location.
//
// Query, body and cookie names come from params.json — common hidden,
// debug, feature-flag and access-control parameter names. Header names come
// from headers.json, which leans on the proxy, routing and caching headers
// that matter behind a CDN or a load balancer: the inputs that change a
// response without being part of its cache key (X-Forwarded-Host,
// X-Original-URL, X-Real-IP and the like).
//
// The lists are bundled data, extensible by the user (a setting, and
// optionally their own file passed as extra names). Names already present
// in the request are left out: a parameter the request already carries is
// not a hidden one.

import type { Location } from "./detect";
import PARAMS from "../params.json";
import HEADERS from "../headers.json";

/** candidatesFor returns the names to guess at a location: the bundled list
 *  for that location, plus the user's extras, minus what the request
 *  already has, de-duplicated case-insensitively. */
export function candidatesFor(location: Location, extra: string[], existing: string[]): string[] {
  const bundled = location === "header" ? (HEADERS as string[]) : (PARAMS as string[]);
  const have = new Set(existing.map((n) => n.toLowerCase()));
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of [...bundled, ...extra]) {
    const name = raw.trim();
    if (!name) continue;
    const key = name.toLowerCase();
    if (have.has(key) || seen.has(key)) continue;
    seen.add(key);
    out.push(name);
  }
  return out;
}

/** The counts, for the catalog and for tests. */
export function bundledCounts(): { params: number; headers: number } {
  return { params: (PARAMS as string[]).length, headers: (HEADERS as string[]).length };
}
