// What shows that a host runs Laravel.
//
// Nothing here is worth a finding on its own: the point is to know whether
// the rest of the plugin should speak at all. A cookie-attribute finding on
// an app that isn't Laravel would be this plugin talking about traffic that
// is none of its business, so a host has to be shown to run Laravel first.
//
// Evidence comes in two strengths. A strong signal is something only a
// Laravel app does — an encrypted Laravel cookie, a path from one of its
// packages, its vendor directory named in a page. A weak one is something
// Laravel does that plenty of other stacks do too, and two of those are
// needed before the host is called Laravel. The verdict is written into the
// finding, so the tester can judge the evidence rather than trust the
// label.

import { type Cookie, type CookieKind, encrypted } from "./cookies";

export interface Signal {
  /** What was seen, as the finding's notes will put it. */
  why: string;
  strong: boolean;
}

/** Paths that belong to a Laravel package and to nothing else. */
const PACKAGE_PATHS: { prefix: string; why: string }[] = [
  { prefix: "/_ignition/", why: "the /_ignition/ route Laravel's error page registers" },
  { prefix: "/_debugbar/", why: "the /_debugbar/ route the Laravel Debugbar registers" },
  { prefix: "/livewire/", why: "the /livewire/ route Livewire registers" },
  { prefix: "/sanctum/csrf-cookie", why: "Laravel Sanctum's /sanctum/csrf-cookie route" },
  { prefix: "/vendor/telescope/", why: "Laravel Telescope's published assets" },
  { prefix: "/vendor/horizon/", why: "Laravel Horizon's published assets" },
  { prefix: "/vendor/pulse/", why: "Laravel Pulse's published assets" },
  { prefix: "/vendor/laravel/", why: "a file served straight out of vendor/laravel/" },
];

/** Needles searched in a lower-cased body. */
const HTML_SIGNALS: { needle: string; why: string; strong: boolean }[] = [
  { needle: "vendor/laravel/framework", strong: true, why: "the path vendor/laravel/framework in the response" },
  { needle: "/_debugbar/assets", strong: true, why: "the Laravel Debugbar's assets in the page" },
  { needle: "/livewire/livewire.js", strong: true, why: "Livewire's script in the page" },
  { needle: "wire:snapshot", strong: true, why: "a Livewire component in the page" },
  { needle: "window.livewire", strong: true, why: "Livewire's runtime in the page" },
  { needle: "laravel-vapor", strong: true, why: "Laravel Vapor's asset helper in the page" },
  { needle: "illuminate\\", strong: true, why: "an Illuminate class name in the response" },
  { needle: '"csrf-token"', strong: false, why: 'a <meta name="csrf-token"> tag, as Laravel\'s scaffolding ships' },
  { needle: "/build/assets/", strong: false, why: "assets under /build/, where Laravel's Vite plugin puts them" },
  { needle: "mix-manifest.json", strong: false, why: "a Laravel Mix manifest" },
];

export function fromPath(path: string): Signal[] {
  const p = path.toLowerCase();
  const out: Signal[] = [];
  for (const s of PACKAGE_PATHS) {
    if (p.indexOf(s.prefix) === 0) out.push({ why: s.why, strong: true });
  }
  return out;
}

/** html must be lower-cased; the needles are. */
export function fromHtml(html: string): Signal[] {
  const out: Signal[] = [];
  for (const s of HTML_SIGNALS) {
    if (html.indexOf(s.needle) >= 0) out.push({ why: s.why, strong: s.strong });
  }
  return out;
}

export function fromCookie(c: Cookie, kind: CookieKind): Signal | undefined {
  if (kind === "csrf") {
    return encrypted(c.value)
      ? { why: "an encrypted XSRF-TOKEN cookie", strong: true }
      : { why: "an XSRF-TOKEN cookie", strong: false };
  }
  if (c.name.toLowerCase() === "laravel_session") {
    return { why: "the laravel_session cookie", strong: true };
  }
  if (kind === "remember") return { why: `the remember-me cookie ${c.name}`, strong: true };
  if (encrypted(c.value)) return { why: `${c.name}, an encrypted Laravel cookie`, strong: true };
  return undefined;
}

/** The Debugbar sends its data in headers when the response isn't HTML. */
export function fromHeaders(headers: { name: string; value: string }[]): Signal[] {
  const out: Signal[] = [];
  for (const h of headers) {
    const n = h.name.toLowerCase();
    if (n === "phpdebugbar-id" || n.indexOf("phpdebugbar") === 0) {
      out.push({ why: `the ${h.name} header the Laravel Debugbar adds`, strong: true });
      break;
    }
  }
  return out;
}

/**
 * Whether the signals add up to Laravel, and the sentence that says why.
 * One strong signal is enough; otherwise two weak ones are needed.
 */
export function verdict(signals: Signal[]): { laravel: boolean; why: string; certain: boolean } {
  const seen: string[] = [];
  let strong = 0;
  for (const s of signals) {
    if (seen.indexOf(s.why) >= 0) continue;
    seen.push(s.why);
    if (s.strong) strong++;
  }
  const laravel = strong > 0 || seen.length >= 2;
  return { laravel, why: seen.join("; "), certain: strong > 0 };
}
