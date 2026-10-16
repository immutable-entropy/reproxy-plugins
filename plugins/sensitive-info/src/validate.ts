// The checks that keep a match from becoming a finding: a card number that
// fails Luhn, an IBAN whose checksum is wrong, a value that is only a
// placeholder. They are what makes broad patterns usable — the patterns
// find candidates, these decide whether the candidate is real.

/** decodeForm undoes form encoding (%xx and +), leaving a bad escape alone. */
export function decodeForm(v: string): string {
  if (v.indexOf("%") < 0 && v.indexOf("+") < 0) return v;
  try {
    return decodeURIComponent(v.replace(/\+/g, " "));
  } catch {
    return v;
  }
}

/** digits returns just the digits of a value: "4111-1111" -> "41111111". */
export function digits(v: string): string {
  return v.replace(/[^0-9]/g, "");
}

// Values that are not secrets: a masked field, a template hole, a sample
// from documentation. "test" and "password" are deliberately absent — in a
// test environment they are real credentials, and flagging them is the point.
const placeholders =
  /^(?:null|undefined|nil|none|nan|true|false|n\/?a|-+|\.+|\?+|0|1|changeme|change_me|change-me|redacted|hidden|removed|your[_-]?[a-z0-9_-]*|my[_-]?(?:api[_-]?key|secret|token|password)|insert[_-]?[a-z0-9_-]*|placeholder|replace[_-]?me|sample|dummy|xxxxx*|notset|not[_-]?set|empty|unset)$/i;

/** isPlaceholder reports whether a value carries no secret: masked, empty,
 *  a template hole ({{token}}, ${PASSWORD}, <your key>, :password) or one of
 *  the words used to stand in for a secret. */
export function isPlaceholder(v: string): boolean {
  const t = v.trim();
  if (t === "" || t.length > 4096) return true;
  if (placeholders.test(t)) return true;
  // Masked: "********", "••••1234", "xxxx-xxxx-xxxx-1234".
  if (/^[*•·●•x\s.\-_]+[0-9]{0,6}$/i.test(t)) return true;
  // Template holes left for the client or the server to fill in.
  if (/^(?:\{\{.*\}\}|\$\{.*\}|<[^>]*>|%[sdv]|:[a-z_]+|\[[a-z_ ]+\]|\$[A-Z_]{3,})$/i.test(t)) return true;
  return false;
}

/** luhn checks a card number's check digit. */
export function luhn(number: string): boolean {
  const d = digits(number);
  if (d.length < 12 || d.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

/** validIban checks an IBAN's length and its mod-97 checksum. */
export function validIban(v: string): boolean {
  const s = v.replace(/[\s-]/g, "").toUpperCase();
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}$/.test(s)) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  // mod 97 a digit at a time, so the number never has to be held whole.
  let rem = 0;
  for (const c of moved) {
    const n = c >= "A" ? c.charCodeAt(0) - 55 : c.charCodeAt(0) - 48;
    rem = n > 9 ? (rem * 100 + n) % 97 : (rem * 10 + n) % 97;
  }
  return rem === 1;
}

/** plausibleSsn rejects the US Social Security numbers that can't be issued
 *  (area 000, 666 or 900-999, group 00, serial 0000), which is what most
 *  nnn-nn-nnnn false positives look like. */
export function plausibleSsn(v: string): boolean {
  const d = digits(v);
  if (d.length !== 9) return false;
  const area = d.slice(0, 3);
  if (area === "000" || area === "666" || area[0] === "9") return false;
  if (d.slice(3, 5) === "00" || d.slice(5) === "0000") return false;
  // 123-45-6789 and friends are examples, not people.
  return d !== "123456789" && d !== "078051120" && d !== "219099999";
}

/** plausiblePhone reports whether a value could be a telephone number:
 *  7 to 15 digits, and not a year, a price or an identifier. */
export function plausiblePhone(v: string): boolean {
  const d = digits(v);
  if (d.length < 7 || d.length > 15) return false;
  if (/^0+$/.test(d)) return false;
  // A run of one digit, or a straight count, is test data at best.
  return !/^(\d)\1+$/.test(d) && d !== "1234567890";
}

/** plausibleDate reports whether a value looks like a date of birth:
 *  ISO, d/m/y or m/d/y, or a Unix timestamp. */
export function plausibleDate(v: string): boolean {
  const t = v.trim();
  if (/^\d{4}-\d{2}-\d{2}(?:[T ].*)?$/.test(t)) return true;
  if (/^\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}$/.test(t)) return true;
  if (/^\d{8}$/.test(t)) return true; // 19800101
  return /^-?\d{9,13}$/.test(t); // epoch seconds or milliseconds
}

// Hash shapes, by what they look like rather than what made them.
const hexHash = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{56}$|^[0-9a-f]{64}$|^[0-9a-f]{96}$|^[0-9a-f]{128}$/i;
const cryptFormat = /^\$(?:1|2[abxy]?|5|6|y|argon2(?:id|i|d)|scrypt|s2k|sha1|P|H|apr1)\$/;
const prefixed = /^(?:\{(?:SHA|SSHA|MD5|SMD5|CRYPT|SSHA256|SSHA512)\}|pbkdf2(?:[_-]sha[0-9]+)?\$|sha(?:1|256|512)\$|bcrypt_sha256\$|argon2|\*[0-9A-F]{40}$)/i;

/** looksLikeHash reports whether a value is a digest or a stored password
 *  hash: a known crypt format, or raw hex of a digest's length. */
export function looksLikeHash(v: string): boolean {
  const t = v.trim();
  if (cryptFormat.test(t) || prefixed.test(t)) return true;
  if (hexHash.test(t)) return true;
  // Base64 of a 16, 20, 32 or 64-byte digest.
  return /^[A-Za-z0-9+/]{22,24}={0,2}$|^[A-Za-z0-9+/]{27,28}={0,2}$|^[A-Za-z0-9+/]{43,44}={0,2}$|^[A-Za-z0-9+/]{86,88}={0,2}$/.test(t);
}

/** decodeBase64 decodes base64 to text, as UTF-8, or returns null if it
 *  isn't base64 of text. The runtime's TextDecoder never throws, so bad
 *  UTF-8 is spotted by the replacement characters it leaves behind. */
export function decodeBase64(v: string): string | null {
  let b64 = v.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  let bin: string;
  try {
    bin = atob(b64);
  } catch {
    return null;
  }
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const text = new TextDecoder().decode(bytes);
  // A replacement character or a control character means it was bytes,
  // not text.
  return /[\ufffd\u0000-\u0008\u000e-\u001f]/.test(text) ? null : text;
}
