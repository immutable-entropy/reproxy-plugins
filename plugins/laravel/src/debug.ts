// Reading a Laravel error page.
//
// APP_DEBUG=true in production is the misconfiguration this plugin exists
// for. With it on, an uncaught exception is answered with Ignition's page
// (Laravel 6 and later), Whoops' page (Laravel 5), or — when the request
// asked for JSON — a reply carrying the exception class, the file, the line
// and the whole stack trace. Any of them hands over the application's
// directory layout on the server, the frameworks and versions it runs, the
// SQL it was executing and, on Whoops' "Server/Request Data" table and in
// Ignition's context, the process environment: APP_KEY, DB_PASSWORD and
// whatever else the deployment puts in the environment.
//
// The page is large, so it is read the cheap way round: indexOf over a
// lower-cased copy decides what kind of page it is, and only then are the
// patterns run — every one of them anchored on a literal (APP_KEY,
// "laravel_version", <title>), so Go's regexp can jump between candidates
// instead of walking the body. test/cost.test.ts holds that to a budget.

import { text } from "reproxy";

export interface DebugError {
  kind: "ignition" | "whoops" | "symfony" | "json";
  /** What showed it, for the finding's notes. */
  evidence: string;
  /** True when the page itself names Laravel (as against some other PHP app). */
  laravel: boolean;
  /** The exception's class, where the page states it. */
  exception: string;
  /** The exception's message, or the page's title. */
  message: string;
  /** The source file and line the exception came from. */
  file: string;
  line: string;
  laravelVersion: string;
  phpVersion: string;
  /** APP_ENV as the page reports it: "production" here is its own finding. */
  appEnv: string;
  /** The application's directory on the server, when a path gives it away. */
  root: string;
  /** Names — never values — of environment variables the page printed. */
  envNames: string[];
  /** The APP_KEY, when the page printed it. */
  appKey: string;
}

/**
 * Environment variables worth naming when an error page prints the process
 * environment. The names are what the finding reports; the values are left
 * to the sensitive-info plugin, which recognises far more of them.
 */
const ENV_NAMES = [
  "APP_KEY",
  "APP_ENV",
  "APP_DEBUG",
  "DB_HOST",
  "DB_DATABASE",
  "DB_USERNAME",
  "DB_PASSWORD",
  "REDIS_PASSWORD",
  "MAIL_HOST",
  "MAIL_USERNAME",
  "MAIL_PASSWORD",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_BUCKET",
  "PUSHER_APP_SECRET",
  "STRIPE_SECRET",
  "MAILGUN_SECRET",
  "JWT_SECRET",
  "SENTRY_LARAVEL_DSN",
  "BROADCAST_CONNECTION",
];

const VENDOR = "/vendor/laravel/framework";
/** The same path as a JSON string inside a page: PHP escapes every slash. */
const VENDOR_JSON = "\\/vendor\\/laravel\\/framework";

/** Patterns, each anchored on a literal so a large body stays cheap. */
const P_LARAVEL_VERSION = '"laravel_version"\\s*:\\s*"([^"]{1,40})"';
const P_PHP_VERSION = '"php_version"\\s*:\\s*"([^"]{1,40})"';
const P_APP_ENV = '"app_env"\\s*:\\s*"([^"]{1,40})"';
const P_TITLE = "(?is)<title>(.{0,300}?)</title>";
const P_APP_KEY = "(?s)APP_KEY.{0,300}?(base64:[A-Za-z0-9+/=]{30,100})";

/**
 * readHtmlError reads an HTML error page. lower must be a lower-cased copy
 * of html; the caller already has one for its own needles.
 */
export function readHtmlError(html: string, lower: string): DebugError | undefined {
  const kind = pageKind(lower);
  if (!kind) return undefined;

  const e: DebugError = {
    kind,
    evidence: evidenceFor(kind),
    laravel: lower.indexOf(VENDOR) >= 0 || lower.indexOf("illuminate\\") >= 0 || lower.indexOf("laravel_version") >= 0,
    exception: "",
    message: "",
    file: "",
    line: "",
    laravelVersion: "",
    phpVersion: "",
    appEnv: "",
    root: rootOf(html),
    envNames: envNames(html),
    appKey: "",
  };

  // One pass per pattern, each stopping at its first match: every one is
  // anchored on a literal, so Go's regexp searches for that literal rather
  // than walking the body.
  e.laravelVersion = first(html, P_LARAVEL_VERSION);
  e.phpVersion = first(html, P_PHP_VERSION);
  e.appEnv = first(html, P_APP_ENV);
  e.message = tidy(first(html, P_TITLE));
  e.appKey = appKeyIn(html);

  return e;
}

/** readJsonError reads the reply Laravel sends an exception to a JSON client. */
export function readJsonError(value: unknown): DebugError | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const v = value as Record<string, unknown>;
  // With debug off the reply is {"message": "Server Error"} and nothing
  // else. These four fields together are what debug mode adds.
  if (typeof v.exception !== "string" || typeof v.file !== "string") return undefined;
  if (v.line === undefined || !Array.isArray(v.trace)) return undefined;

  const file = v.file;
  const exception = v.exception;
  return {
    kind: "json",
    evidence: `a JSON reply carrying "exception", "file", "line" and a ${v.trace.length}-frame "trace", which Laravel only sends when APP_DEBUG is true`,
    laravel: exception.indexOf("Illuminate\\") === 0 || file.indexOf(VENDOR) >= 0,
    exception,
    message: typeof v.message === "string" ? tidy(v.message) : "",
    file,
    line: String(v.line),
    laravelVersion: "",
    phpVersion: "",
    appEnv: "",
    root: rootOf(file),
    envNames: [],
    appKey: "",
  };
}

/**
 * appKeyIn reads an APP_KEY out of whatever printed it: an error page's
 * environment table, or an exposed .env. The pattern is anchored on the
 * literal APP_KEY, so it is cheap however large the text is.
 */
export function appKeyIn(body: string): string {
  return first(body, P_APP_KEY);
}

function pageKind(lower: string): DebugError["kind"] | undefined {
  if (lower.indexOf("whoops, looks like something went wrong") >= 0) return "whoops";
  if (lower.indexOf("whoops") >= 0 && lower.indexOf("stack frames") >= 0) return "whoops";
  if (lower.indexOf("laravel_version") >= 0) return "ignition";
  if (lower.indexOf("_ignition") >= 0 || lower.indexOf("ignition.js") >= 0) return "ignition";
  if (lower.indexOf("ignition") >= 0 && lower.indexOf("flare") >= 0) return "ignition";
  if (lower.indexOf("sf-dump") >= 0 || lower.indexOf("symfony\\component\\errorhandler") >= 0) return "symfony";
  // A page that names the framework's own source and a stack trace is a
  // debug page whichever handler rendered it.
  if (lower.indexOf(VENDOR) >= 0 && (lower.indexOf("stack trace") >= 0 || lower.indexOf("exception") >= 0)) {
    return "symfony";
  }
  return undefined;
}

function evidenceFor(kind: DebugError["kind"]): string {
  switch (kind) {
    case "ignition":
      return "Ignition's error page, which Laravel renders only when APP_DEBUG is true";
    case "whoops":
      return "the Whoops error page, which Laravel 5 renders only when APP_DEBUG is true";
    default:
      return "an unhandled exception rendered with its source and stack trace, which needs APP_DEBUG to be true";
  }
}

/** The environment variable names an error page printed. */
function envNames(html: string): string[] {
  const out: string[] = [];
  for (const name of ENV_NAMES) {
    if (html.indexOf(name) >= 0) out.push(name);
  }
  // One name on its own is nothing: Ignition's own context mentions
  // APP_ENV and APP_DEBUG in lower case, and a page may simply say the
  // words. Several upper-case names together is the environment table.
  return out.length >= 3 ? out : [];
}

/**
 * rootOf takes the application's directory on the server from the path of
 * the framework's own source, which every stack trace contains. Walking
 * back from a literal is cheaper than a pattern with no literal to anchor
 * on, and it gives the one path worth reporting.
 */
function rootOf(file: string): string {
  let at = file.indexOf(VENDOR);
  let escaped = false;
  if (at < 0) {
    // An error page embeds its data as JSON, and PHP escapes slashes there.
    at = file.indexOf(VENDOR_JSON);
    escaped = true;
  }
  if (at < 0) return "";
  let start = at;
  // A directory path, not a sentence: stop at the first character that
  // could not be in one, and never walk back further than a long path.
  while (start > 0 && at - start < 200 && isPathChar(file.charAt(start - 1))) start--;
  const root = escaped ? file.slice(start, at).split("\\/").join("/") : file.slice(start, at);
  return root.length > 1 && root.charAt(0) === "/" ? root : "";
}

/** The first match's first group, or "". */
function first(html: string, pattern: string): string {
  const found = text.scan(html, [pattern], 1);
  return found.length > 0 ? (found[0].groups[0] || "").trim() : "";
}

function isPathChar(c: string): boolean {
  return /[A-Za-z0-9._\-\/\\]/.test(c);
}

function tidy(s: string): string {
  const flat = s.replace(/<[^>]{0,200}>/g, " ").replace(/\s+/g, " ").trim();
  return flat.length > 200 ? flat.slice(0, 197) + "…" : flat;
}
