// Laravel's cookies, and what their attributes say about the session
// configuration behind them.
//
// Laravel encrypts every cookie it sets (EncryptCookies middleware), so a
// Laravel cookie's value is base64 of {"iv":"…","value":"…","mac":"…"} and
// begins with eyJpdiI6I. That prefix is how a renamed session cookie is
// still recognised as Laravel's, and how a cookie the app has excluded from
// encryption stands out.
//
// Three cookies matter. The session cookie (laravel_session unless
// SESSION_COOKIE says otherwise) is the credential: whoever holds it is
// logged in. The remember-me cookie is the same thing with a five-year
// life. XSRF-TOKEN is the CSRF token, and is deliberately readable by
// JavaScript — Laravel's own Axios configuration reads it — so a missing
// HttpOnly on it is the design, not a mistake.
//
// A head is small, so this is plain string work: no text.scan is needed.

/** One header line, as Message.headers gives it. */
export interface Header {
  name: string;
  value: string;
}

export interface Cookie {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  /** "lax", "strict", "none", or "" when the attribute was not sent. */
  sameSite: string;
  maxAge: string;
}

/**
 * What a cookie is to Laravel: the session credential, the remember-me
 * token, the CSRF token, some other cookie the app encrypted, or nothing
 * of ours.
 */
export type CookieKind = "session" | "remember" | "csrf" | "encrypted" | "";

export interface CookieIssue {
  id: string;
  /** Names the problem in the finding's value: "without HttpOnly". */
  short: string;
  note: string;
  fix: string;
}

/** Base64 of the start of Laravel's encrypted cookie payload, {"iv":". */
const ENCRYPTED = "eyJpdiI6I";

/** The Set-Cookie lines of a response. */
export function setCookies(headers: Header[]): string[] {
  const out: string[] = [];
  for (const h of headers) {
    if (h.name.toLowerCase() === "set-cookie") out.push(h.value);
  }
  return out;
}

export function parseSetCookie(lines: string[]): Cookie[] {
  const out: Cookie[] = [];
  for (const line of lines) {
    const parts = line.split(";");
    const eq = parts[0].indexOf("=");
    if (eq <= 0) continue;
    const c: Cookie = {
      name: parts[0].slice(0, eq).trim(),
      value: parts[0].slice(eq + 1).trim(),
      secure: false,
      httpOnly: false,
      sameSite: "",
      maxAge: "",
    };
    for (let i = 1; i < parts.length; i++) {
      const attr = parts[i].trim();
      const j = attr.indexOf("=");
      const key = (j < 0 ? attr : attr.slice(0, j)).toLowerCase();
      const value = j < 0 ? "" : attr.slice(j + 1).trim();
      if (key === "secure") c.secure = true;
      else if (key === "httponly") c.httpOnly = true;
      else if (key === "samesite") c.sameSite = value.toLowerCase();
      else if (key === "max-age") c.maxAge = value;
    }
    out.push(c);
  }
  return out;
}

/** True when the value is one of Laravel's encrypted payloads. */
export function encrypted(value: string): boolean {
  return value.indexOf(ENCRYPTED) === 0;
}

export function kindOf(c: Cookie): CookieKind {
  const name = c.name.toLowerCase();
  if (name === "xsrf-token") return "csrf";
  if (name.indexOf("remember_") === 0) return "remember";
  if (name === "laravel_session") return "session";
  if (!encrypted(c.value)) return "";
  // A renamed session cookie is still called something_session by almost
  // every app that renames it; anything else the app encrypted is reported
  // only for being sent in the clear, since a cookie meant to be read by
  // its own JavaScript is a choice, not a mistake.
  return name.indexOf("session") >= 0 ? "session" : "encrypted";
}

/** What a cookie is, in words, for the notes. */
export function describe(kind: CookieKind): string {
  switch (kind) {
    case "session":
      return "Laravel's session cookie — the credential that says who is logged in";
    case "remember":
      return "Laravel's remember-me cookie, a login token that is valid for five years by default";
    case "csrf":
      return "Laravel's XSRF-TOKEN cookie, the CSRF token the front end reads and echoes back";
    default:
      return "a cookie Laravel encrypted";
  }
}

/**
 * What is wrong with one cookie. https says whether the response that set
 * it came over TLS: Secure only has something to say there, since a site
 * served over http has a larger problem than its cookie attributes.
 */
export function issues(c: Cookie, kind: CookieKind, https: boolean): CookieIssue[] {
  const out: CookieIssue[] = [];
  if (kind === "") return out;
  const credential = kind === "session" || kind === "remember";

  if (https && !c.secure) {
    out.push({
      id: "no_secure",
      short: "without Secure",
      note:
        "The cookie has no Secure attribute, so the browser will also send it over plain http — to a " +
        "link, an image or a redirect that slipped onto http, or to an attacker who can put one there. " +
        (credential ? "That hands over the session itself." : "That exposes the token to anyone on the path."),
      fix: "Set SESSION_SECURE_COOKIE=true (config/session.php, 'secure'), which covers every cookie Laravel sets.",
    });
  }
  if (credential && !c.httpOnly) {
    out.push({
      id: "no_httponly",
      short: "without HttpOnly",
      note:
        "The cookie has no HttpOnly attribute, so any JavaScript running on the page can read it. One " +
        "cross-site scripting bug anywhere on the origin is then enough to take the session, with no need " +
        "to ride it.",
      fix: "Set SESSION_HTTP_ONLY=true (config/session.php, 'http_only'); Laravel's default is true, so this was turned off.",
    });
  }
  if (c.sameSite === "none" && !c.secure) {
    out.push({
      id: "samesite_none_insecure",
      short: "with SameSite=None and no Secure",
      note:
        "SameSite=None asks the browser to send the cookie on cross-site requests, and browsers only " +
        "honour that with Secure set. As sent, the cookie is both cross-site and plaintext — current " +
        "browsers reject it outright, so this is likely to be breaking the site as well.",
      fix: "Set SESSION_SECURE_COOKIE=true, or drop back to 'same_site' => 'lax' in config/session.php.",
    });
  } else if (credential && c.sameSite === "") {
    out.push({
      id: "no_samesite",
      short: "without SameSite",
      note:
        "No SameSite attribute was sent. Laravel's default is 'lax', so config/session.php has 'same_site' " +
        "=> null. Browsers now treat a missing attribute as Lax of their own accord, which limits the " +
        "practical damage, but the app is no longer stating what it wants and older clients will send " +
        "the cookie on any cross-site request.",
      fix: "Set 'same_site' => 'lax' in config/session.php (the framework default), or 'strict' if the app never needs cross-site navigation to stay logged in.",
    });
  } else if (credential && c.sameSite === "none" && c.secure) {
    out.push({
      id: "samesite_none",
      short: "with SameSite=None",
      note:
        "SameSite=None sends the cookie on every cross-site request, so the only thing standing between " +
        "another origin's form and a state change is Laravel's CSRF token. Check that the VerifyCsrfToken " +
        "middleware is on these routes and that nothing is in its $except list.",
      fix: "Use 'same_site' => 'lax' in config/session.php unless a cross-site embed genuinely needs the session.",
    });
  }
  if (kind === "session" && !encrypted(c.value)) {
    out.push({
      id: "not_encrypted",
      short: "sent unencrypted",
      note:
        "The value is not one of Laravel's encrypted payloads, so this cookie has probably been added to " +
        "the $except list of the EncryptCookies middleware. The session ID is then readable and writable " +
        "as sent, which is what the encryption and its MAC exist to prevent: it opens the way to session " +
        "fixation, and to probing the session driver with an ID of the tester's choosing.",
      fix: "Take the cookie out of EncryptCookies::$except (app/Http/Middleware/EncryptCookies.php).",
    });
  }
  return out;
}
