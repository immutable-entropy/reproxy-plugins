// Sensitive values that only their field name gives away: a password, a
// user name, a card number, a date of birth. A value like "hunter2" says
// nothing on its own; "password=hunter2" says everything.
//
// One composed pattern finds every assignment whose name carries a word
// worth looking at — in a query string, a JSON or form body, a multipart
// part, an XML element or a header line — and the rules below decide what
// the name means and whether the value is worth reporting. Keeping the name
// filter in the pattern (in Go) and the judgement in TypeScript is what
// makes this one pass over the body instead of fifteen.

import { entropy } from "./entropy";
import type { FindingType } from "./formats";
import type { Branch } from "./pattern";
import {
  decodeForm,
  digits,
  isPlaceholder,
  looksLikeHash,
  luhn,
  plausibleDate,
  plausiblePhone,
  plausibleSsn,
  validIban,
} from "./validate";

// Words that may appear anywhere in a field's name: long enough that a
// chance substring is unlikely.
const LOOSE = [
  "password",
  "passwd",
  "passwort",
  "passphrase",
  "pwd",
  "secret",
  "credential",
  "apikey",
  "api[_.-]?key",
  "access[_.-]?key",
  "access[_.-]?token",
  "auth[_.-]?token",
  "id[_.-]?token",
  "refresh[_.-]?token",
  "bearer",
  "session",
  "jsessionid",
  "phpsessid",
  "csrf",
  "xsrf",
  "private[_.-]?key",
  "client[_.-]?secret",
  "app[_.-]?secret",
  "security[_.-]?token",
  "sas[_.-]?token",
  "username",
  "user[_.-]?name",
  "login",
  "screen[_.-]?name",
  "e[_.-]?mail",
  "msisdn",
  "telephone",
  "cellphone",
  "passport",
  "licen[cs]e",
  "social[_.-]?security",
  "national[_.-]?id",
  "routing[_.-]?number",
  "account[_.-]?number",
  "sort[_.-]?code",
  "card[_.-]?number",
  "cardnumber",
  "credit[_.-]?card",
  "birth",
  "tax[_.-]?id",
  "taxid",
  "recovery[_.-]?code",
  "backup[_.-]?code",
  "verification[_.-]?code",
  "two[_.-]?factor",
  "bcrypt",
  "pbkdf2",
  "hashed",
  "digest",
  "md5",
  "sha1",
  "sha256",
  "sha512",
  "ntlm",
];

// Words that count only as a whole part of a name, so "sid" matches
// "sid" and "x_sid" but not "inside", and "key" doesn't match "monkey".
const STRICT = ["pass", "key", "token", "auth", "user", "uid", "mail", "phone", "mobile", "tel", "cell", "dob", "card", "pan", "pin", "otp", "totp", "mfa", "sid", "ssn", "nino", "sin", "iban", "cvv", "cvc", "csc", "hash", "salt"];

/**
 * FIELD_ANCHORS are the literals a body must hold for any of these names to
 * be in it: each keyword above cut at its first pattern character, with the
 * ones a shorter anchor already covers dropped. A body none of them appears
 * in cannot hold a named field worth reading, and is never put through the
 * pattern (see detectors.ts).
 */
export const FIELD_ANCHORS: string[] = anchorsOf([...LOOSE, ...STRICT]);

function anchorsOf(keywords: string[]): string[] {
  const literals = keywords
    .map((k) => k.split(/[[(?|\\]/)[0])
    .filter((k) => k.length >= 3);
  // Shortest first, so a longer anchor a shorter one already covers goes.
  literals.sort((a, b) => a.length - b.length || (a < b ? -1 : 1));
  const out: string[] = [];
  for (const k of literals) {
    let covered = false;
    for (const kept of out) {
      if (k.indexOf(kept) >= 0) {
        covered = true;
        break;
      }
    }
    if (!covered) out.push(k);
  }
  return out;
}

const NAME_CHARS = `[A-Za-z0-9_.\\[\\]-]`;
const NAME =
  `(?:${NAME_CHARS}{0,32}(?:${LOOSE.join("|")})${NAME_CHARS}{0,32}` +
  `|(?:[A-Za-z0-9]{1,24}[_.-])?(?:${STRICT.join("|")})(?:[_.-]${NAME_CHARS}{0,24})?)`;

// Where an assignment can be written. Each branch captures the name and the
// value, in that order.
const BEFORE = `(?:^|[?&;,{\\[(\\s])`;
const QUOTE = `["']?`;
const ASSIGN = `[ \\t]*(?::|=|=>)[ \\t]*`;

/** FIELD_BRANCHES are the shapes an assignment takes, quoted values first. */
export const FIELD_BRANCHES: Branch[] = [
  // "password": "hunter2"
  { id: "quoted", pattern: `(?i)${BEFORE}${QUOTE}(${NAME})${QUOTE}${ASSIGN}["']([^"'\\r\\n]{1,256})["']` },
  // password=hunter2, password: hunter2
  { id: "bare", pattern: `(?i)${BEFORE}${QUOTE}(${NAME})${QUOTE}${ASSIGN}([^\\s"'&;,<>\\]}]{1,256})` },
  // a multipart/form-data part
  { id: "multipart", pattern: `(?i)name=["'](${NAME})["'][^\\r\\n]{0,200}\\r?\\n(?:[A-Za-z-]{2,40}:[^\\r\\n]{0,100}\\r?\\n){0,3}\\r?\\n([^\\r\\n]{1,256})` },
  // <password>hunter2</password>
  { id: "element", pattern: `(?i)<(${NAME})(?:[ \\t][^>\\r\\n]{0,200})?>[ \\t]*([^<\\r\\n]{1,256})` },
];

/** What a field's name turned out to mean. */
export interface Field {
  id: string;
  label: string;
  type: FindingType;
  value: string;
  note?: string;
  /** True when it is only worth reporting beside a credential (a user name
   *  in a response is not a login). */
  needsCredential?: boolean;
}

interface Rule {
  id: string;
  label: string;
  type: FindingType;
  names: RegExp;
  note?: string;
  needsCredential?: boolean;
  /** Turns the value into what to record, or null to drop it. */
  check?: (value: string, minEntropy: number) => string | null;
}

// Names that look sensitive but hold nothing: a flag about a password, a
// label for a field, a count of logins.
// Header and framework names that carry one of the words above but hold
// nothing: User-Agent, Sec-Fetch-User, WWW-Authenticate.
const DENY =
  /(?:^|_)(?:author|authors|authoring|passenger|bypass|compass|keyboard|monkey|authorization|proxy_authorization|authenticate|www_authenticate|agent|fetch_user|ch_ua|content|accept)(?:_|$)/;
const DENY_SUFFIX =
  /_(?:strength|length|len|expired|expires|expiry|verified|confirmed|count|attempts|enabled|disabled|required|optional|type|kind|brand|label|url|uri|link|placeholder|hint|policy|policies|rules|min|max|size|format|mask|masked|last4|last_four|visible|status|flag|error|message|regex|pattern|at|on|by|id_type)$/;
const DENY_PREFIX = /^(?:has|is|show|use|needs|need|require|requires|allow|allows|can|should|with|no|total|num)_/;

/** norm puts a field's name in one form: user[newPassword] -> user_new_password. */
export function norm(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function looksRandom(v: string, minEntropy: number): boolean {
  if (entropy(v) >= minEntropy) return true;
  // A long mixed-case-and-digits value is a key even when its character
  // spread is narrow (a 40-character hex token, say).
  return v.length >= 32 && /[A-Za-z]/.test(v) && /[0-9]/.test(v);
}

const RULES: Rule[] = [
  {
    id: "field_hash",
    label: "Password hash",
    type: "hash",
    names: /(?:^|_)(?:hash|hashed|hashed_password|password_hash|pwhash|passhash|digest|md5|sha1|sha256|sha512|ntlm|bcrypt|pbkdf2|crypt)(?:_|$)/,
    note: "A hash is enough to crack offline, and for some schemes enough to replay as it is.",
    check: (v) => (looksLikeHash(v) ? v : null),
  },
  {
    id: "field_salt",
    label: "Password salt",
    type: "hash",
    names: /(?:^|_)salt(?:_|$)/,
    note: "A salt is only useful to an attacker who also has the hash, but it should not be published either.",
    check: (v) => (v.length >= 8 && !/^[0-9]{1,12}$/.test(v) ? v : null),
  },
  {
    id: "field_password",
    label: "Password",
    type: "credential",
    names: /(?:^|_)(?:password|passwd|passwort|passphrase|pwd|pass)(?:_|$)/,
    note: "A password in the clear can be read by anything between the browser and the server.",
    check: (v) => v,
  },
  {
    id: "field_pin",
    label: "One-time or PIN code",
    type: "credential",
    names: /(?:^|_)(?:pin|otp|totp|mfa|two_factor|2fa|recovery_code|backup_code|verification_code|sms_code)(?:_|$)/,
    check: (v) => (/^[A-Za-z0-9-]{4,24}$/.test(v) ? v : null),
  },
  {
    id: "field_api_key",
    label: "API key or secret",
    type: "secret-key",
    names: /(?:^|_)(?:api_key|apikey|client_secret|app_secret|secret_key|secret|private_key|access_key|credential|credentials|key)(?:_|$)/,
    note: "A key in traffic the client can read is a key the client's user can keep.",
    check: (v, min) => (v.length >= 8 && looksRandom(v, min) ? v : null),
  },
  {
    id: "field_token",
    label: "Token",
    type: "token",
    names: /(?:^|_)(?:token|bearer|jwt|security_token|sas_token|auth)(?:_|$)/,
    note: "A token is a credential for as long as it is valid.",
    check: (v, min) => (v.length >= 8 && looksRandom(v, min) ? v : null),
  },
  {
    id: "field_session",
    label: "Session identifier",
    type: "token",
    names: /(?:^|_)(?:session|sessionid|session_id|sid|jsessionid|phpsessid|csrf|csrf_token|xsrf|xsrf_token)(?:_|$)/,
    note: "Whoever holds a session identifier is that session.",
    check: (v) => (v.length >= 8 && entropy(v) >= 2.5 ? v : null),
  },
  {
    id: "field_card",
    label: "Payment card number",
    type: "payment-data",
    names: /(?:^|_)(?:card|card_number|cardnumber|cc_number|ccnum|credit_card|pan)(?:_|$)/,
    note: "Card numbers in traffic put the application in scope for PCI DSS.",
    check: (v) => (luhn(v) ? v : null),
  },
  {
    id: "field_cvv",
    label: "Card security code",
    type: "payment-data",
    names: /(?:^|_)(?:cvv|cvv2|cvc|cvc2|csc|card_security_code)(?:_|$)/,
    note: "A card security code may never be stored, even encrypted.",
    check: (v) => (/^[0-9]{3,4}$/.test(v) ? v : null),
  },
  {
    id: "field_bank",
    label: "Bank account detail",
    type: "payment-data",
    names: /(?:^|_)(?:iban|bic|swift|account_number|accountnumber|routing_number|sort_code|sortcode)(?:_|$)/,
    check: (v) => {
      if (/^[A-Z]{2}[0-9]{2}/i.test(v.replace(/\s/g, ""))) return validIban(v) ? v : null;
      const d = digits(v);
      return d.length >= 6 && d.length <= 18 ? v : null;
    },
  },
  {
    id: "field_gov_id",
    label: "Government identifier",
    type: "personal-data",
    names: /(?:^|_)(?:ssn|social_security|social_security_number|national_id|nino|sin|tax_id|taxid|passport|passport_number|passport_no|driver_licence|driver_license|licence_number|license_number)(?:_|$)/,
    check: (v, _min) => {
      if (/^[0-9]{3}-?[0-9]{2}-?[0-9]{4}$/.test(v)) return plausibleSsn(v) ? v : null;
      return /^[A-Za-z0-9 -]{5,24}$/.test(v) && /[0-9]/.test(v) ? v : null;
    },
  },
  {
    id: "field_dob",
    label: "Date of birth",
    type: "personal-data",
    names: /(?:^|_)(?:dob|birth_date|birthdate|date_of_birth|birthday|birth)(?:_|$)/,
    check: (v) => (plausibleDate(v) ? v : null),
  },
  {
    id: "field_phone",
    label: "Telephone number",
    type: "personal-data",
    names: /(?:^|_)(?:phone|phone_number|mobile|mobile_number|msisdn|tel|telephone|cell|cellphone)(?:_|$)/,
    check: (v) => (plausiblePhone(v) ? v : null),
  },
  {
    id: "field_email",
    label: "Email address",
    type: "personal-data",
    names: /(?:^|_)(?:email|e_mail|mail|email_address|user_email|contact_email)(?:_|$)/,
    check: (v) => (/^[^@\s]{1,64}@[^@\s]{1,253}\.[A-Za-z]{2,24}$/.test(v) ? v : null),
  },
  {
    id: "field_username",
    label: "User name",
    type: "credential",
    names: /(?:^|_)(?:user|username|user_name|login|login_name|uid|screen_name|account_name)(?:_|$)/,
    note: "The account half of a login, beside the password it was sent with.",
    needsCredential: true,
    // A name, an address or a handle — not "?1" or a number.
    check: (v) => (/^[A-Za-z0-9][A-Za-z0-9._%+@-]{0,99}$/.test(v) && !/^[0-9]+$/.test(v) ? v : null),
  },
];

/**
 * classify decides what an assignment holds: the rule its name matches and
 * the value to record, or null when the name means nothing to us or the
 * value holds nothing.
 */
export function classify(rawName: string, rawValue: string, minEntropy: number): Field | null {
  const name = norm(rawName);
  if (!name || DENY.test(name) || DENY_SUFFIX.test(name) || DENY_PREFIX.test(name)) return null;
  const value = decodeForm(rawValue.trim()).trim();
  if (isPlaceholder(value)) return null;
  for (const r of RULES) {
    if (!r.names.test(name)) continue;
    const kept = r.check ? r.check(value, minEntropy) : value;
    if (kept === null) continue;
    // A password stored as its hash is a hash, whatever the field is called.
    if (r.type === "credential" && r.id === "field_password" && kept.length >= 20 && looksLikeHash(kept)) {
      return { id: "field_hash", label: "Password hash", type: "hash", value: kept, note: RULES[0].note };
    }
    return {
      id: r.id,
      label: r.label,
      type: r.type,
      value: kept,
      note: r.note,
      needsCredential: r.needsCredential,
    };
  }
  return null;
}
