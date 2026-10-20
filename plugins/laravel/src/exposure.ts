// Things a Laravel deployment serves that it should not.
//
// Two mistakes account for nearly all of them. The first is leaving a
// development tool routed in production — Telescope, Horizon, Pulse, the
// Debugbar, Clockwork, Ignition, a log viewer — each of which was installed
// to show everything the application does, and does exactly that for
// whoever reaches it. The second is pointing the web server's document root
// at the project directory instead of its public/ subdirectory, which puts
// .env, composer.json, storage/ and vendor/ on the web.
//
// Each rule is a path to look for and something in the body that confirms
// it, because the path alone proves nothing: a single-page app answers 200
// with its own shell for /telescope as happily as for any other route. A
// rule that cannot confirm says nothing at all.

import { text } from "reproxy";

export interface Exposure {
  id: string;
  /** Names the thing in the finding's value: "Telescope dashboard". */
  label: string;
  /** What it is and what it gives away. */
  note: string;
  fix: string;
  /** True when finding it is itself proof the app is Laravel. */
  laravel: boolean;
  /** Anything the body added, for the notes. */
  extra?: string;
  fields?: Record<string, string>;
}

/** What a rule's body check returns: undefined when it isn't confirmed. */
interface Confirmed {
  extra?: string;
  fields?: Record<string, string>;
}

interface Rule {
  id: string;
  label: string;
  note: string;
  fix: string;
  laravel: boolean;
  /** path is lower-cased and has no query. */
  match(path: string): boolean;
  /** lower is a lower-cased copy of body. */
  confirm(body: string, lower: string, contentType: string): Confirmed | undefined;
}

/** The document root should be public/; everything else stays above it. */
const DOC_ROOT_FIX =
  "Point the web server's document root at the project's public/ directory. Nothing above it — .env, " +
  "composer.json, storage/, vendor/, artisan — is meant to be reachable over HTTP.";

const RULES: Rule[] = [
  {
    id: "env_file",
    label: "The .env file is served",
    laravel: true,
    note:
      "The application's .env is being served. It is the whole configuration in one file: APP_KEY, the " +
      "database host, user and password, mail and queue credentials, and whatever API keys the deployment " +
      "holds. APP_KEY alone lets an attacker forge and decrypt every cookie, session payload and signed " +
      "URL the app issues.",
    fix: DOC_ROOT_FIX + " Then rotate every credential in the file: assume all of them are known.",
    match: (p) => p === "/.env" || endsWith(p, "/.env") || p.indexOf("/.env.") === 0,
    confirm: (body) =>
      has(body, "APP_KEY=") || has(body, "APP_ENV=") || has(body, "APP_NAME=") || has(body, "DB_DATABASE=")
        ? { fields: envFields(body) }
        : undefined,
  },
  {
    id: "storage_logs",
    label: "The application log is served",
    laravel: true,
    note:
      "Laravel's log file is being served. Every stack trace the application has written is in it, with " +
      "the file paths, SQL and exception messages that go with them — and, wherever the code logs a " +
      "request or a model, the user data and tokens it was handling.",
    fix: DOC_ROOT_FIX + " storage/ holds logs, compiled views, sessions and cache files, and belongs above it.",
    match: (p) => p.indexOf("/storage/logs/") >= 0,
    confirm: (body, lower) =>
      lower.indexOf(".error:") >= 0 ||
      lower.indexOf(".info:") >= 0 ||
      lower.indexOf(".debug:") >= 0 ||
      lower.indexOf("stack trace:") >= 0
        ? {}
        : undefined,
  },
  {
    id: "storage_private",
    label: "A private storage file is served",
    laravel: true,
    note:
      "A file under storage/app or storage/framework is being served. That is the private side of the " +
      "application's disk: uploads not meant to be public, compiled Blade views, cached configuration and " +
      "file-driver sessions. A session file read from here is someone's live session.",
    fix: DOC_ROOT_FIX + " Only storage/app/public, linked into public/storage by `php artisan storage:link`, is meant to be reachable.",
    match: (p) =>
      (p.indexOf("/storage/app/") >= 0 && p.indexOf("/storage/app/public/") < 0) || p.indexOf("/storage/framework/") >= 0,
    // Whatever came back, something under storage/ was served; a binary
    // body reads as empty text, so the media type stands in for it.
    confirm: (body, _lower, contentType) => (body.length > 0 || contentType !== "" ? {} : undefined),
  },
  {
    id: "telescope",
    label: "Telescope is reachable",
    laravel: true,
    note:
      "Laravel Telescope's dashboard answered. Telescope records everything the application does — every " +
      "request with its payload and headers, every SQL query with its bindings, mail, notifications, " +
      "queued jobs, cache keys, scheduled commands and the exceptions they threw — and replays it to " +
      "whoever opens the page. Credentials sent to the app in a login request are in those recorded " +
      "payloads.",
    fix:
      "Telescope is restricted by the gate in app/Providers/TelescopeServiceProvider.php, which allows " +
      "everyone when APP_ENV is local. Either keep TELESCOPE_ENABLED=false outside development, or write " +
      "a gate that names the people allowed to view it.",
    match: (p) => p === "/telescope" || p.indexOf("/telescope/") === 0,
    confirm: (body, lower) =>
      lower.indexOf("/vendor/telescope/") >= 0 || lower.indexOf("window.telescope") >= 0 || lower.indexOf("telescope-api") >= 0
        ? {}
        : undefined,
  },
  {
    id: "horizon",
    label: "Horizon is reachable",
    laravel: true,
    note:
      "Laravel Horizon's dashboard answered. It lists the queues and their jobs with the payloads they " +
      "carry, the failed jobs and their exceptions, and it can retry or delete them — so reaching it is " +
      "both a view of the work the application does and a way to make it do that work again.",
    fix:
      "Horizon is restricted by the viewHorizon gate in app/Providers/HorizonServiceProvider.php, which " +
      "allows everyone when APP_ENV is local. Define that gate for production.",
    match: (p) => p === "/horizon" || p.indexOf("/horizon/") === 0,
    confirm: (body, lower) =>
      lower.indexOf("/vendor/horizon/") >= 0 || lower.indexOf("window.horizon") >= 0 || lower.indexOf("horizon/api/") >= 0
        ? {}
        : undefined,
  },
  {
    id: "pulse",
    label: "Pulse is reachable",
    laravel: true,
    note:
      "Laravel Pulse's dashboard answered. It shows the application's slow queries and the SQL behind " +
      "them, slow requests and jobs, the exceptions being thrown and the users making the most requests " +
      "— an operational picture of the production system, and a list of its weak points.",
    fix: "Define the viewPulse gate (app/Providers/AppServiceProvider.php) so it names the people allowed to view it; Pulse allows everyone when APP_ENV is local.",
    match: (p) => p === "/pulse" || p.indexOf("/pulse/") === 0,
    confirm: (body, lower) =>
      lower.indexOf("/vendor/pulse/") >= 0 || lower.indexOf("pulse-dashboard") >= 0 ? {} : undefined,
  },
  {
    id: "debugbar",
    label: "The Debugbar's routes are reachable",
    laravel: true,
    note:
      "A route the Laravel Debugbar registers answered. The Debugbar collects the queries a request ran " +
      "with their bindings, the session and request data, the views rendered and the mail sent, and " +
      "/_debugbar/open serves what it collected for earlier requests — other people's, not just yours.",
    fix:
      "Set DEBUGBAR_ENABLED=false (or leave it unset and APP_DEBUG=false, which is what the package " +
      "follows), and install barryvdh/laravel-debugbar with --dev so it cannot be routed in production.",
    match: (p) => p.indexOf("/_debugbar/") === 0,
    confirm: () => ({}),
  },
  {
    id: "ignition",
    label: "Ignition's routes are reachable",
    laravel: true,
    note:
      "One of the /_ignition/ routes answered. Ignition is the package behind Laravel's debug error page; " +
      "its routes exist to let the page run fixes against the application, and they are registered " +
      "whenever the package is installed and debug mode is on.",
    fix:
      "Set APP_DEBUG=false in production, and check the installed version of facade/ignition or " +
      "spatie/laravel-ignition: with debug on, versions before facade/ignition 2.5.2 allow unauthenticated " +
      "remote code execution through execute-solution (CVE-2021-3129).",
    match: (p) => p.indexOf("/_ignition/") === 0,
    confirm: (body, lower) => {
      if (lower.indexOf("can_execute_commands") < 0) return {};
      const can = lower.indexOf('"can_execute_commands":true') >= 0 || lower.indexOf('"can_execute_commands": true') >= 0;
      return {
        extra: can
          ? "Its health check answers can_execute_commands: true, so the solution-running routes are live, not just routed."
          : "Its health check answers can_execute_commands: false.",
        fields: { can_execute_commands: can ? "true" : "false" },
      };
    },
  },
  {
    id: "clockwork",
    label: "Clockwork is reachable",
    laravel: true,
    note:
      "Clockwork's data endpoint answered. Clockwork profiles each request and keeps what it saw — the " +
      "queries and their bindings, the session, the cookies, the request and response, the log lines — " +
      "and serves it back by request id, so anyone who reaches it can read the traffic of everyone else.",
    fix: "Set CLOCKWORK_ENABLE=false outside development, and require itsgoingd/clockwork with --dev.",
    match: (p) => p.indexOf("/__clockwork/") === 0 || p.indexOf("/clockwork/") === 0,
    confirm: (body, lower) =>
      lower.indexOf("clockwork") >= 0 || lower.indexOf("databasequeries") >= 0 ? {} : undefined,
  },
  {
    id: "log_viewer",
    label: "A log viewer is reachable",
    laravel: true,
    note:
      "A log-viewer page answered. These packages read everything under storage/logs and render it in the " +
      "browser, so reaching one is the same as being served the application's log file — stack traces, " +
      "file paths, queries and whatever the application logs about its users.",
    fix: "Gate the viewer's routes behind authentication (every one of these packages has a gate or middleware setting), or remove the package from production.",
    match: (p) => p === "/log-viewer" || p.indexOf("/log-viewer/") === 0,
    confirm: (body, lower) =>
      lower.indexOf("log-viewer") >= 0 || lower.indexOf("logviewer") >= 0 || lower.indexOf("log viewer") >= 0 ? {} : undefined,
  },
  {
    id: "composer_file",
    label: "composer.json or composer.lock is served",
    laravel: true,
    note:
      "The project's Composer manifest is being served. It lists every package the application depends on " +
      "— composer.lock with the exact version of each — which turns finding a vulnerable dependency into " +
      "reading a file. That the file is reachable at all means the document root is wrong, so .env is " +
      "worth trying next.",
    fix: DOC_ROOT_FIX,
    match: (p) => p === "/composer.json" || p === "/composer.lock",
    confirm: (body) => {
      if (!has(body, '"laravel/framework"')) return undefined;
      const version = frameworkVersion(body);
      return version ? { extra: `It gives laravel/framework as ${version}.`, fields: { laravel_framework: version } } : {};
    },
  },
  {
    id: "project_file",
    label: "A project file above public/ is served",
    laravel: true,
    note:
      "A file from the project directory — artisan, or something out of vendor/ — is being served, so the " +
      "web server's document root is the project itself rather than its public/ directory. Everything in " +
      "the project is then reachable, .env included.",
    fix: DOC_ROOT_FIX,
    match: (p) => p === "/artisan" || p === "/vendor/autoload.php" || p.indexOf("/vendor/composer/") === 0 || p.indexOf("/vendor/laravel/") === 0,
    confirm: (body, _lower, contentType) => (body.length > 0 || contentType !== "" ? {} : undefined),
  },
];

/**
 * What a response at this path exposes, or undefined when the path is one
 * of ours but the body doesn't bear it out.
 */
export function exposureFor(path: string, contentType: string, body: string, lower?: string): Exposure | undefined {
  const p = stripQuery(path).toLowerCase();
  for (const r of RULES) {
    if (!r.match(p)) continue;
    const got = r.confirm(body, lower === undefined ? body.toLowerCase() : lower, contentType);
    if (!got) return undefined;
    return { id: r.id, label: r.label, note: r.note, fix: r.fix, laravel: r.laravel, extra: got.extra, fields: got.fields };
  }
  return undefined;
}

/** The variables an exposed .env sets, by name only. */
function envFields(body: string): Record<string, string> {
  const names: string[] = [];
  for (const m of text.scan(body, ["(?m)^\\s*([A-Z][A-Z0-9_]{2,40})\\s*="], 200)) {
    const name = m.groups[0];
    if (name && names.indexOf(name) < 0) names.push(name);
  }
  return names.length > 0 ? { variables: String(names.length), names: names.slice(0, 40).join(", ") } : {};
}

/** The laravel/framework version a composer.json or composer.lock states. */
function frameworkVersion(body: string): string {
  const lock = text.scan(body, ['"laravel/framework"[\\s\\S]{0,400}?"version"\\s*:\\s*"([^"]{1,30})"'], 1);
  if (lock.length > 0 && lock[0].groups[0]) return lock[0].groups[0];
  const json = text.scan(body, ['"laravel/framework"\\s*:\\s*"([^"]{1,30})"'], 1);
  return json.length > 0 ? json[0].groups[0] || "" : "";
}

function has(body: string, needle: string): boolean {
  return body.indexOf(needle) >= 0;
}

function endsWith(s: string, suffix: string): boolean {
  return s.length >= suffix.length && s.slice(s.length - suffix.length) === suffix;
}

function stripQuery(path: string): string {
  const q = path.indexOf("?");
  return q < 0 ? path : path.slice(0, q);
}
