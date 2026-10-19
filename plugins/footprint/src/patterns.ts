// Footprint items that aren't ordinary links, so text.urls doesn't find
// them: third-party service identifiers (analytics, error reporting, chat),
// mailto: and tel: links, s3:// bucket URIs, postal addresses in a page's
// structured data, and email addresses and telephone numbers in the text
// itself.
//
// Each is looked for with a literal-anchored RE2 pattern run in Go
// (text.scan). The patterns that could match are chosen first by a plain
// indexOf for each one's anchor over a lower-cased copy of the body, so a
// body that can't hold a thing never has its pattern run — the same cost
// discipline the sensitive-info plugin keeps. The one exception is email
// and telephone text, which has no literal to anchor on and so is read over
// a bounded slice of the body (maxPii).

import { text } from "reproxy";
import type { FindingType, Hit } from "./links";
import { digits, isPlaceholder, plausiblePhone } from "./validate";

export interface Options {
  /** The most of the body the un-anchored email and phone patterns read. */
  maxPii: number;
  /** Email domains (and their subdomains) never to report. */
  ignoreEmails: string[];
  /** The most matches text.scan returns per pattern. */
  max: number;
}

interface Spec {
  id: string;
  type: FindingType;
  label: string;
  /** Lower-case literals; the pattern runs only if the body holds one. */
  anchors: string[];
  pattern: string;
  /** The capture group holding the value (0 = the first group); the whole
   *  match when absent. */
  group?: number;
  note?: string;
  valid?: (v: string) => boolean;
  fields?: (v: string) => Record<string, string>;
}

/** The anchored specs: a body is searched only for the ones its text could hold. */
const SPECS: Spec[] = [
  {
    id: "email_mailto",
    type: "contact",
    label: "Email address",
    anchors: ["mailto:"],
    pattern: `(?i)mailto:([A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,253}\\.[A-Za-z]{2,24})`,
    group: 0,
  },
  {
    id: "phone_tel",
    type: "contact",
    label: "Telephone number",
    anchors: ["tel:"],
    pattern: `(?i)tel:(\\+?[0-9().\\s-]{5,30})`,
    group: 0,
    valid: plausiblePhone,
  },
  {
    id: "s3_uri",
    type: "cloud-storage",
    label: "AWS S3 bucket",
    anchors: ["s3://"],
    pattern: `(?i)s3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])`,
    group: 0,
    note: "A storage bucket named in a response is worth checking for public listing and world-readable objects.",
    fields: (v) => ({ provider: "AWS S3", bucket: v }),
  },
  {
    id: "ga4",
    type: "service-id",
    label: "Google Analytics 4 measurement id",
    anchors: ["g-"],
    pattern: `\\bG-[A-Z0-9]{9,11}\\b`,
    note: "A Google Analytics id links the site to the organisation's analytics account and the other properties under it.",
  },
  {
    id: "ua",
    type: "service-id",
    label: "Google Analytics (Universal) property id",
    anchors: ["ua-"],
    pattern: `\\bUA-[0-9]{4,10}-[0-9]{1,4}\\b`,
    note: "A Universal Analytics id links the site to the organisation's analytics account.",
  },
  {
    id: "gtm",
    type: "service-id",
    label: "Google Tag Manager container id",
    anchors: ["gtm-"],
    pattern: `\\bGTM-[A-Z0-9]{5,8}\\b`,
    note: "A Tag Manager container id identifies the organisation's GTM account.",
  },
  {
    id: "sentry_dsn",
    type: "service-id",
    label: "Sentry DSN",
    anchors: ["sentry.io", ".ingest."],
    pattern: `https://[0-9a-f]{16,64}@[A-Za-z0-9.-]+\\.ingest\\.[A-Za-z0-9.-]*sentry\\.io/[0-9]+`,
    note: "A Sentry DSN is a public ingestion key; it names the Sentry organisation and project, and can be used to send events.",
  },
  {
    id: "stripe_pk",
    type: "service-id",
    label: "Stripe publishable key",
    anchors: ["pk_live_", "pk_test_"],
    pattern: `\\bpk_(?:live|test)_[A-Za-z0-9]{16,99}\\b`,
    note: "A Stripe publishable key is meant to be public, but it names the Stripe account and whether it is in live or test mode.",
  },
  {
    id: "fb_pixel",
    type: "service-id",
    label: "Facebook Pixel id",
    anchors: ["fbq("],
    pattern: `(?i)fbq\\(\\s*['"]init['"]\\s*,\\s*['"]([0-9]{15,16})['"]`,
    group: 0,
    note: "A Facebook Pixel id ties the site to the organisation's Facebook advertising account.",
  },
  {
    id: "segment_key",
    type: "service-id",
    label: "Segment write key",
    anchors: ["analytics.load("],
    pattern: `(?i)analytics\\.load\\(\\s*["']([A-Za-z0-9]{10,40})["']`,
    group: 0,
    note: "A Segment write key is used from the browser to send events; it names the organisation's Segment source.",
  },
  {
    id: "intercom_app",
    type: "service-id",
    label: "Intercom app id",
    anchors: ["intercom"],
    pattern: `(?i)intercom[\\s\\S]{0,160}?app_id["'\\s:=]+([a-z0-9]{6,10})\\b`,
    group: 0,
    note: "An Intercom app id identifies the organisation's Intercom workspace.",
  },
  {
    id: "postal_address",
    type: "contact",
    label: "Postal address",
    anchors: ["streetaddress"],
    pattern: `(?i)"street[_]?address"\\s*:\\s*"([^"\\r\\n]{3,160})"`,
    group: 0,
    note: "A postal address from the page's structured data (schema.org).",
  },
];

/** The plain-text patterns, read over a bounded slice: they have no literal
 *  to anchor on, so they are the only ones that read the body itself. */
const EMAIL = `\\b[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]{1,63}(?:\\.[A-Za-z0-9-]{1,63}){0,8}\\.[A-Za-z]{2,24}\\b`;
const PHONE = `\\+[1-9][0-9]{7,14}\\b`;

/** scan reads a body for every footprint item that isn't an ordinary link. */
export function scan(body: string, opts: Options): Hit[] {
  const out: Hit[] = [];
  const seen = new Set<string>();
  const add = (h: Hit | null): void => {
    if (!h || !h.value || isPlaceholder(h.value)) return;
    const key = `${h.type}\u0000${h.value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(h);
  };

  const lower = body.toLowerCase();
  const active = SPECS.filter((s) => s.anchors.some((a) => lower.indexOf(a) >= 0));
  if (active.length > 0) {
    for (const m of text.scan(body, active.map((s) => ({ name: s.id, pattern: s.pattern })), opts.max)) {
      const spec = active.find((s) => s.id === m.pattern);
      if (!spec) continue;
      let value = ((spec.group !== undefined ? m.groups[spec.group] : m.match) ?? "").trim();
      if (!value) continue;
      if (spec.valid && !spec.valid(value)) continue;
      if (spec.type === "contact" && (spec.id === "email_mailto") && !keepEmail(value, opts.ignoreEmails)) continue;
      add({ type: spec.type, detector: spec.id, label: spec.label, value, note: spec.note, fields: spec.fields ? spec.fields(value) : undefined });
    }
  }

  // Email and telephone text: no anchor, so bounded by maxPii.
  const slice = body.length > opts.maxPii ? body.slice(0, opts.maxPii) : body;
  if (slice.indexOf("@") >= 0) {
    for (const m of text.scan(slice, [{ name: "email", pattern: EMAIL }], opts.max)) {
      const value = m.match.trim();
      if (keepEmail(value, opts.ignoreEmails)) add({ type: "contact", detector: "email", label: "Email address", value });
    }
  }
  if (slice.indexOf("+") >= 0) {
    for (const m of text.scan(slice, [{ name: "phone", pattern: PHONE }], opts.max)) {
      const value = m.match.trim();
      if (plausiblePhone(value)) add({ type: "contact", detector: "phone", label: "Telephone number", value });
    }
  }
  return out;
}

/** keepEmail drops the addresses that aren't a person's or an organisation's:
 *  an ignored domain, and the asset names (logo@2x.png) that look like one. */
export function keepEmail(value: string, ignore: string[]): boolean {
  const at = value.indexOf("@");
  if (at <= 0) return false;
  const domain = value.slice(at + 1).toLowerCase();
  if (/\.(?:png|jpe?g|gif|svg|webp|avif|css|js|mjs|ico|woff2?|ttf|map)$/.test(domain)) return false;
  // "2x.png" style retina asset names, and version strings.
  if (/^[0-9]/.test(value) && digits(value.slice(0, at)).length >= value.slice(0, at).length - 1) return false;
  for (const d of ignore) {
    const i = d.toLowerCase().replace(/^@/, "").trim();
    if (i && (domain === i || domain.endsWith("." + i))) return false;
  }
  return true;
}
