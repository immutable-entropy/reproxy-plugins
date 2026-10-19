// What a host's key/value store says about its certificates, and how a
// lookup that only one service answered is merged into what an earlier
// lookup left there.

import type { NameSummary } from "./certs";

/** The keys this plugin writes on a host. */
export const keys = {
  certificates: "ct.certificates",
  wildcards: "ct.wildcard_certificates",
  issuers: "ct.issuers",
  firstIssued: "ct.first_issued",
  latestExpiry: "ct.latest_expiry",
  sources: "ct.sources",
  sharedWith: "ct.shares_certificate_with",
};

/** The key/value notes for one host name. Empty values are left unset. */
export function notesFor(s: NameSummary): Record<string, string> {
  return {
    [keys.certificates]: s.certificates ? String(s.certificates) : "",
    [keys.wildcards]: s.wildcardCertificates ? String(s.wildcardCertificates) : "",
    [keys.issuers]: s.issuers.join(", "),
    [keys.firstIssued]: s.firstIssued,
    [keys.latestExpiry]: s.latestExpiry,
    [keys.sources]: s.sources.join(", "),
    [keys.sharedWith]: s.sharedWith.slice(0, 10).join(", ") + (s.sharedWith.length > 10 ? ", …" : ""),
  };
}

/**
 * Merge fresh notes into the ones a host already has, for a lookup that
 * only one service answered: what it didn't see may still be true. Lists
 * are joined, counts keep the larger, the first issue the earlier and the
 * expiry the later. A lookup both services answered replaces the notes
 * instead, so that what has expired since drops out.
 */
export function mergeNotes(old: Record<string, string>, fresh: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = { ...fresh };
  const list = (k: string) => {
    const items: string[] = [];
    for (const v of [fresh[k], old[k]]) {
      for (const i of (v || "").split(", ")) if (i && i !== "…" && items.indexOf(i) < 0) items.push(i);
    }
    out[k] = items.join(", ");
  };
  const count = (k: string) => {
    const n = Math.max(Number(fresh[k]) || 0, Number(old[k]) || 0);
    out[k] = n ? String(n) : "";
  };
  const pick = (k: string, later: boolean) => {
    const a = fresh[k] || "";
    const b = old[k] || "";
    out[k] = !a ? b : !b ? a : (a > b) === later ? a : b;
  };
  count(keys.certificates);
  count(keys.wildcards);
  list(keys.issuers);
  list(keys.sources);
  list(keys.sharedWith);
  pick(keys.firstIssued, false);
  pick(keys.latestExpiry, true);
  if (out[keys.sources]) out[keys.sources] = out[keys.sources].split(", ").sort().join(", ");
  return out;
}
