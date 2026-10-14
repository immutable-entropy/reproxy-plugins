// Reading a decoded SAML document for what a tester should review.
//
// SAML's XML is parsed here with small, targeted regular expressions rather
// than a full XML parser (there is none in the runtime). That is enough for
// the elements that matter: the Subject/NameID the assertion is about, the
// AttributeStatement it carries, the Conditions that bound it, and whether a
// Signature is present. Each concern it surfaces becomes a finding.

import type { SamlBlob } from "./decode";
import { decodeClaims } from "./jwt";

export interface Options {
  flagAttributes: boolean;
  flagWeaknesses: boolean;
  maxAgeHours: number;
  sensitive: string[];
}

export type ConcernType = "saml-assertion" | "saml-subject" | "saml-attribute" | "saml-weakness";

export interface Concern {
  type: ConcernType;
  title: string;
  detail: string;
  value: string;
  where: string;
  container: string;
  fields: Record<string, string>;
}

/** inspect reads a SAML document and returns what is worth reviewing. */
export function inspect(xml: string, blob: SamlBlob, opts: Options): Concern[] {
  const out: Concern[] = [];
  const container = containerName(xml, blob);
  const push = (c: Omit<Concern, "container">) => out.push({ ...c, container });

  // The NameID: who the assertion is about. Often an email or a persistent
  // identifier worth noting.
  const nameId = tagContent(xml, "NameID");
  if (nameId) {
    const format = attr(firstTag(xml, "NameID") || "", "Format") || "unspecified";
    push({
      type: "saml-subject",
      title: "Subject NameID",
      detail: `Format: ${short(format)}. This identifies the authenticated principal.`,
      value: nameId.trim(),
      where: "Subject/NameID",
      fields: { format, nameid: nameId.trim() },
    });
  }

  // Attributes: the claims the IdP asserts about the user. Flag sensitive
  // names always, and all of them when the setting asks.
  for (const a of attributes(xml)) {
    const lower = a.name.toLowerCase().replace(/[^a-z0-9]/g, "");
    const sensitive = opts.sensitive.some((s) => lower.includes(s.replace(/[^a-z0-9]/g, "")));
    if (!sensitive && !opts.flagAttributes) continue;
    const fields: Record<string, string> = { attribute: a.name, values: a.values.join(" | ") };
    let jwtDetail = "";
    for (const v of a.values) {
      const claims = looksLikeJwt(v) ? decodeClaims(v) : null;
      if (claims) {
        Object.assign(fields, claims);
        jwtDetail = " It carries a JWT, whose claims are decoded below.";
      }
    }
    push({
      type: "saml-attribute",
      title: sensitive ? "Sensitive SAML attribute" : "SAML attribute",
      detail:
        (sensitive
          ? "This attribute name looks sensitive; confirm it should be released to this service."
          : "An attribute released in the assertion.") + jwtDetail,
      value: `${a.name}=${a.values.join(", ")}`,
      where: `Attribute ${a.name}`,
      fields,
    });
  }

  if (opts.flagWeaknesses) {
    out.push(...weaknesses(xml, container, opts.maxAgeHours));
  }

  // If nothing else fired, still record that a SAML assertion passed, so the
  // tester knows the exchange happened and can open it.
  if (out.length === 0 && /<(?:[A-Za-z][\w.-]*:)?Assertion\b/.test(xml)) {
    push({
      type: "saml-assertion",
      title: "SAML assertion",
      detail: "A SAML assertion was exchanged. Review its subject, attributes and conditions.",
      value: issuerOf(xml) || "SAML assertion",
      where: "Assertion",
      fields: { issuer: issuerOf(xml) },
    });
  }
  return out;
}

function weaknesses(xml: string, container: string, maxAgeHours: number): Concern[] {
  const out: Concern[] = [];
  const add = (title: string, detail: string, where: string, value: string) =>
    out.push({ type: "saml-weakness", title, detail, value, where, container, fields: { issuer: issuerOf(xml) } });

  const hasAssertion = /<(?:[A-Za-z][\w.-]*:)?Assertion\b/.test(xml);
  if (hasAssertion && !/<(?:[A-Za-z][\w.-]*:)?Signature\b/.test(xml)) {
    add("Unsigned SAML assertion", "The assertion carries no XML Signature. An unsigned assertion can be forged or tampered with.", "Assertion", issuerOf(xml) || "unsigned assertion");
  }

  // Bearer subject confirmation without a Recipient restriction is a replay
  // risk.
  const scd = firstTag(xml, "SubjectConfirmationData");
  const conf = firstTag(xml, "SubjectConfirmation") || "";
  if (/bearer/i.test(attr(conf, "Method")) && scd && !attr(scd, "Recipient")) {
    add("Bearer subject without a Recipient", "A bearer SubjectConfirmation with no Recipient can be replayed to another service.", "SubjectConfirmationData", "bearer, no recipient");
  }

  // A long validity window widens the replay opportunity.
  const cond = firstTag(xml, "Conditions") || "";
  const notBefore = attr(cond, "NotBefore");
  const notAfter = attr(cond, "NotOnOrAfter");
  if (notBefore && notAfter) {
    const span = (Date.parse(notAfter) - Date.parse(notBefore)) / 3_600_000;
    if (!Number.isNaN(span) && span > maxAgeHours) {
      add(
        "Long assertion validity window",
        `The assertion is valid for about ${span.toFixed(1)} hours (${notBefore} to ${notAfter}). A shorter window limits replay.`,
        "Conditions",
        `${notBefore} → ${notAfter}`,
      );
    }
  }
  return out;
}

// ---- Tiny XML helpers (regex-based; the runtime has no XML parser) ----------

const NS = "(?:[A-Za-z][\\w.-]*:)?";

/** firstTag returns the opening tag (with attributes) of the first element. */
export function firstTag(xml: string, local: string): string | null {
  const m = new RegExp(`<${NS}${local}\\b[^>]*>`, "i").exec(xml);
  return m ? m[0] : null;
}

/** tagContent returns the text inside the first <local>…</local>. */
export function tagContent(xml: string, local: string): string | null {
  const m = new RegExp(`<${NS}${local}\\b[^>]*>([\\s\\S]*?)</${NS}${local}>`, "i").exec(xml);
  return m ? decodeEntities(m[1].trim()) : null;
}

/** attr reads an attribute's value from an opening tag. */
export function attr(tag: string, name: string): string {
  const m = new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, "i").exec(tag);
  return m ? m[1] : "";
}

export interface SamlAttribute {
  name: string;
  values: string[];
}

/** attributes reads the AttributeStatement's attributes and their values. */
export function attributes(xml: string): SamlAttribute[] {
  const out: SamlAttribute[] = [];
  const re = new RegExp(`<${NS}Attribute\\b([^>]*)>([\\s\\S]*?)</${NS}Attribute>`, "gi");
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml))) {
    const name = attr(m[1], "FriendlyName") || attr(m[1], "Name");
    if (!name) continue;
    const values: string[] = [];
    const vre = new RegExp(`<${NS}AttributeValue\\b[^>]*>([\\s\\S]*?)</${NS}AttributeValue>`, "gi");
    let v: RegExpExecArray | null;
    while ((v = vre.exec(m[2]))) values.push(decodeEntities(v[1].trim()));
    out.push({ name, values });
  }
  return out;
}

export function issuerOf(xml: string): string {
  return (tagContent(xml, "Issuer") || "").trim();
}

function containerName(xml: string, blob: SamlBlob): string {
  if (/AuthnRequest\b/.test(xml)) return "authentication request";
  if (/LogoutRequest\b/.test(xml)) return "logout request";
  if (/<(?:[A-Za-z][\w.-]*:)?Response\b/.test(xml)) return "response";
  if (/<(?:[A-Za-z][\w.-]*:)?Assertion\b/.test(xml)) return "assertion";
  return blob.kind;
}

function decodeEntities(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function looksLikeJwt(s: string): boolean {
  return /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(s.trim());
}

function short(s: string): string {
  const i = s.lastIndexOf(":");
  return i >= 0 ? s.slice(i + 1) : s;
}
