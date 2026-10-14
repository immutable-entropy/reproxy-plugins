// The detectors: what counts as sensitive, and how to find it.
//
// Every pattern is RE2 (Go's regular expressions) and runs in Go through
// text.scan, which is far faster than the same work in the plugin's own
// code. A detector's value is the whole match, or the group it names; some
// check what they found before it counts (a valid base64 Basic credential,
// enough entropy for a generic key, an email domain not ignored).

import { text } from "reproxy";
import { entropy } from "./entropy";
import { decodeClaims } from "./jwt";

/** A finding type this plugin declares (see plugin.json). */
export type FindingType = "credential" | "secret-key" | "token" | "personal-data";

export interface Detector {
  id: string;
  label: string;
  type: FindingType;
  pattern: string;
  /** The group holding the value; 0 for the whole match. */
  group: number;
  /** The group holding the field's name, if any. */
  keyGroup?: number;
  /** Where to look. */
  where: "header" | "body" | "any";
  /** Turns a match into the value to record, or null to drop it. */
  check?: (value: string, opts: Options) => string | null;
  /** Only reported when another detector also hit in the same message. */
  needs?: string;
}

export interface Options {
  detectors: string[];
  minEntropy: number;
  maxBody: number;
  ignoreEmails: string[];
}

export interface Hit {
  detector: string;
  label: string;
  type: FindingType;
  value: string;
  key: string;
  inHeader: boolean;
  /** Extra key/value detail for the finding, e.g. a JWT's decoded claims. */
  fields?: Record<string, string>;
}

const FIELD_PASSWORD = `pass(?:word|wd|phrase)?|pwd|passwd`;
const FIELD_USER = `user(?:name)?|login|email|e-mail`;

export const DETECTORS: Detector[] = [
  {
    id: "password",
    label: "Password",
    type: "credential",
    // form fields and JSON members named like a password
    pattern: `(?i)(?:^|[&?\\s"'{,])"?((?:[a-z_]*?)(?:${FIELD_PASSWORD})[a-z_]*)"?\\s*(?:=|:\\s*")([^&"\\s][^&"\\r\\n]{0,199})`,
    group: 2,
    keyGroup: 1,
    where: "body",
    check: (v) => (/^[*•x]+$/i.test(v) || v === "null" ? null : decodeForm(v)),
  },
  {
    id: "username",
    label: "Username",
    type: "credential",
    pattern: `(?i)(?:^|[&?\\s"'{,])"?(${FIELD_USER})"?\\s*(?:=|:\\s*")([^&"\\s][^&"\\r\\n]{0,199})`,
    group: 2,
    keyGroup: 1,
    where: "body",
    needs: "password", // a username only matters next to a password
    check: (v) => decodeForm(v),
  },
  {
    id: "basic_auth",
    label: "HTTP Basic credentials",
    type: "credential",
    pattern: `(?im)^(?:proxy-)?authorization:[ \\t]*basic[ \\t]+([A-Za-z0-9+/=]{4,})`,
    group: 1,
    where: "header",
    check: (v) => {
      try {
        const plain = atob(v);
        return plain.indexOf(":") > 0 ? plain : null;
      } catch {
        return null;
      }
    },
  },
  {
    id: "bearer",
    label: "Bearer token",
    type: "token",
    pattern: `(?im)^authorization:[ \\t]*bearer[ \\t]+([A-Za-z0-9\\-._~+/]{8,}=*)`,
    group: 1,
    where: "header",
  },
  {
    id: "jwt",
    label: "JSON Web Token",
    type: "token",
    pattern: `\\beyJ[A-Za-z0-9_-]{5,}\\.eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*`,
    group: 0,
    where: "any",
  },
  {
    id: "aws_key",
    label: "AWS access key",
    type: "secret-key",
    pattern: `\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b`,
    group: 0,
    where: "any",
  },
  {
    id: "github_token",
    label: "GitHub token",
    type: "secret-key",
    pattern: `\\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\\b`,
    group: 0,
    where: "any",
  },
  {
    id: "slack_token",
    label: "Slack token",
    type: "secret-key",
    pattern: `\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b`,
    group: 0,
    where: "any",
  },
  {
    id: "stripe_key",
    label: "Stripe secret key",
    type: "secret-key",
    pattern: `\\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\\b`,
    group: 0,
    where: "any",
  },
  {
    id: "google_api_key",
    label: "Google API key",
    type: "secret-key",
    pattern: `\\bAIza[0-9A-Za-z_-]{35}\\b`,
    group: 0,
    where: "any",
  },
  {
    id: "private_key",
    label: "Private key",
    type: "secret-key",
    pattern: `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[A-Za-z0-9+/=\\s:,.-]+?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----`,
    group: 0,
    where: "body",
  },
  {
    id: "api_key",
    label: "API key",
    type: "secret-key",
    // name = value / "name": "value" assignments of key-like names
    pattern: `(?i)["']?((?:x-)?(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|app[_-]?secret|private[_-]?token))["']?\\s*(?:[:=]|:\\s*")\\s*["']?([A-Za-z0-9_\\-.=+/]{16,200})`,
    group: 2,
    keyGroup: 1,
    where: "any",
    check: (v, o) => (entropy(v) >= o.minEntropy ? v : null),
  },
  {
    id: "email",
    label: "Email address",
    type: "personal-data",
    pattern: `\\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\\.[A-Za-z]{2,24}\\b`,
    group: 0,
    where: "body",
    check: (v, o) => {
      const domain = v.slice(v.indexOf("@") + 1).toLowerCase();
      // asset names such as logo@2x.png look like addresses
      if (/\.(png|jpe?g|gif|svg|webp|css|js|ico)$/.test(domain)) return null;
      for (const d of o.ignoreEmails) {
        const ignored = d.toLowerCase();
        if (domain === ignored || domain.endsWith("." + ignored)) return null;
      }
      return v;
    },
  },
];

function decodeForm(v: string): string {
  try {
    return decodeURIComponent(v.replace(/\+/g, " "));
  } catch {
    return v;
  }
}

/**
 * scan finds the sensitive values in a message: its head (start line and
 * headers) and its body text, as the given side of an exchange.
 */
export function scan(head: string, body: string, side: "request" | "response", opts: Options): Hit[] {
  const enabled = DETECTORS.filter((d) => opts.detectors.indexOf(d.id) >= 0);
  const hits: Hit[] = [];
  const seen: Record<string, boolean> = {};
  const byDetector: Record<string, boolean> = {};

  for (const [part, isHead] of [
    [head, true],
    [body.length > opts.maxBody ? body.slice(0, opts.maxBody) : body, false],
  ] as [string, boolean][]) {
    if (!part) continue;
    const here = enabled.filter((d) => d.where === "any" || (d.where === "header") === isHead);
    if (here.length === 0) continue;
    const matches = text.scan(
      part,
      here.map((d) => ({ name: d.id, pattern: d.pattern })),
    );
    for (const m of matches) {
      const d = here.find((x) => x.id === m.pattern)!;
      let value = d.group === 0 ? m.match : m.groups[d.group - 1] || "";
      value = value.trim();
      if (d.check) {
        const checked = d.check(value, opts);
        if (checked === null) continue;
        value = checked;
      }
      if (!value) continue;
      const key = d.keyGroup ? m.groups[d.keyGroup - 1] || "" : "";
      const id = d.id + "\u0000" + value;
      if (seen[id]) continue;
      seen[id] = true;
      byDetector[d.id] = true;
      const hit: Hit = { detector: d.id, label: d.label, type: d.type, value, key, inHeader: isHead };
      if (d.id === "jwt" || (d.id === "bearer" && value.split(".").length === 3)) {
        const claims = decodeClaims(value);
        if (claims) hit.fields = claims;
      }
      hits.push(hit);
    }
  }
  // A response echoing "username" back is not a login: keep those only
  // beside what they need.
  return hits.filter((h) => {
    const d = DETECTORS.find((x) => x.id === h.detector)!;
    return !d.needs || (byDetector[d.needs] && side === "request");
  });
}
