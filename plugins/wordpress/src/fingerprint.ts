// What a WordPress site says about itself, and how to read it.
//
// WordPress is talkative. Its asset URLs name the plugin or theme that
// enqueued them and carry a version in ?ver=; its pages announce the core
// version in a generator meta; its feeds repeat it; its REST API advertises
// itself in a Link header. None of that needs a request of our own — it is
// all in responses that have already been through the proxy.
//
// Nothing here is certain: a ?ver= is whatever the code that enqueued the
// asset passed, and plugins that pass the core version (or nothing) are
// common. Each reading therefore carries the evidence it came from, and the
// caller decides how much to claim; see main.ts.

import { text as scanner } from "reproxy";

export type FactKind = "core" | "plugin" | "theme" | "user" | "rest-namespace";

/** One thing read about a site. */
export interface Fact {
  kind: FactKind;
  /** The plugin or theme slug, the username, or the REST namespace. Empty for core. */
  name: string;
  /** The version, when something stated one. */
  version?: string;
  /** How it was seen, for the finding's notes. */
  evidence: string;
}

/** What reading a response turned up. */
export interface Reading {
  /** Set when something in it is WordPress's: then the site is one. */
  fingerprint: string;
  facts: Fact[];
}

/**
 * Paths only WordPress serves. A request to one of these, or a link to one,
 * is what identifies a site as WordPress.
 */
const wpPaths = [
  "/wp-content/",
  "/wp-includes/",
  "/wp-admin/",
  "/wp-json",
  "/wp-login.php",
  "/wp-cron.php",
  "/wp-comments-post.php",
  "/wp-signup.php",
  "/wp-activate.php",
  "/wp-trackback.php",
  "/wp-links-opml.php",
  "/wp-sitemap",
  "/xmlrpc.php",
  "rest_route=",
];

/** The WordPress path a path or URL contains, or "" for none. */
export function looksWordPress(pathOrUrl: string): string {
  const p = pathOrUrl.toLowerCase();
  for (const fp of wpPaths) if (p.indexOf(fp) >= 0) return fp;
  return "";
}

const slugRe = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const assetPathRe = /\/wp-content\/(plugins|mu-plugins|themes)\/([^/{}?"'\\]+)/i;
const authorPathRe = /^\/author\/([^/{}?"'\\]+)\/?$/;

/**
 * The facts a single path states: the slug in a /wp-content/ asset path, and
 * the account named by an author archive. version is the asset's ?ver=, when
 * the caller has the query to go with the path.
 */
export function fromPath(path: string, version?: string): Fact[] {
  const out: Fact[] = [];
  const ver = version && versionLike(version) ? version : "";
  const asset = assetPathRe.exec(path);
  if (asset) {
    const name = asset[2].toLowerCase();
    if (slugRe.test(name)) {
      out.push({
        kind: asset[1].toLowerCase() === "themes" ? "theme" : "plugin",
        name,
        version: ver || undefined,
        evidence: ver ? `the asset ${path}?ver=${ver}` : `the asset path ${path}`,
      });
    }
  }
  const author = authorPathRe.exec(path);
  if (author && slugRe.test(author[1].toLowerCase())) {
    out.push({ kind: "user", name: author[1], evidence: `the author archive ${path}` });
  }
  return out;
}

/** The ver= parameter of a query string, if it is a version at all. */
export function versionOf(query: string): string {
  const m = /(?:^|[&;])ver=([^&;#]{1,48})/.exec(query);
  return m && versionLike(m[1]) ? m[1] : "";
}

/**
 * Whether a ?ver= value is a version rather than a cache-buster. Plenty of
 * sites pass a build hash or a timestamp — wordpress.org itself serves
 * ?ver=c98b5143585c3e9f06b27f6a917b65c8 and ?ver=1781196525 — and reporting
 * one of those as "the plugin's version 1781196525" would be worse than
 * reporting no version at all.
 *
 * So: a short number (5, 12), or something dotted that starts with a digit
 * (1.2, 6.4.3, 7.2-alpha-64347). Nothing else.
 */
export function versionLike(v: string): boolean {
  if (!v || v.length > 24 || !/^[0-9]/.test(v)) return false;
  if (/^[0-9]{1,3}$/.test(v)) return true;
  return /^[0-9]+(?:\.[0-9a-z]+(?:[-_.][0-9a-z]+)*)+$/i.test(v);
}

// The patterns bodies are scanned with, in Go (RE2) rather than in the
// plugin: a page is big and goja is slow. They are ordered cheapest and most
// telling first, because scan stops once it has found max matches and a page
// can carry a hundred assets.
//
// \\?/ matches a slash that may be backslash-escaped, so the same patterns
// read a URL inside a JSON string (PHP's json_encode escapes "/" as "\/").
const bodyPatterns = [
  { name: "generator", pattern: `(?i)<meta[^>]*name=["']generator["'][^>]*content=["']([^"']{1,80})["']` },
  { name: "generator", pattern: `(?i)<meta[^>]*content=["']([^"']{1,80})["'][^>]*name=["']generator["']` },
  { name: "feed", pattern: `(?i)wordpress\\.org\\\\?/\\?v=([0-9][0-9a-z._-]{0,31})` },
  { name: "atom", pattern: `(?i)<generator[^>]*wordpress\\.org[^>]*version=["']([0-9][0-9a-z._-]{0,31})["']` },
  { name: "core-asset", pattern: `(?i)\\\\?/wp-includes\\\\?/[^"'\\s<>()?]*\\?[^"'\\s<>()]*ver=([0-9][0-9a-z._-]{0,31})` },
  { name: "rest-link", pattern: `(?i)rel=["']https:\\\\?/\\\\?/api\\.w\\.org\\\\?/["']` },
  { name: "login", pattern: `(?i)\\\\?/wp-login\\.php` },
  {
    name: "asset",
    pattern:
      `(?i)\\\\?/wp-content\\\\?/(plugins|mu-plugins|themes)\\\\?/([a-z0-9][a-z0-9._-]{0,62})\\\\?/` +
      `[^"'\\s<>()?]*(?:\\?[^"'\\s<>()]*ver=([a-z0-9][a-z0-9._-]{0,31}))?`,
  },
];

/**
 * The patterns that prove the page is WordPress's. A generator meta does
 * too, but only when it names WordPress — every other content management
 * system has one as well.
 */
const proves = ["feed", "atom", "core-asset", "rest-link", "login", "asset"];

/** How each pattern's match reads in a finding's notes. */
const evidence: Record<string, string> = {
  generator: "the page's generator meta tag",
  feed: "a feed's generator link (wordpress.org/?v=…)",
  atom: "an Atom feed's generator element",
  "core-asset": "the ?ver= of an asset under /wp-includes/",
  "rest-link": "the REST API's link relation (api.w.org)",
  login: "a link to /wp-login.php",
  asset: "an asset path under /wp-content/",
};

/** The most matches one body is scanned for. */
const maxMatches = 400;

/** Reads a response body: what it shows about the site, and about its code. */
export function read(body: string, max = maxMatches): Reading {
  const out: Reading = { fingerprint: "", facts: [] };
  if (!body) return out;
  for (const m of scanner.scan(body, bodyPatterns, max)) {
    if (!out.fingerprint && proves.indexOf(m.pattern) >= 0) {
      out.fingerprint = evidence[m.pattern] || m.pattern;
    }
    switch (m.pattern) {
      case "generator": {
        // A generator meta names a product and often its version. WordPress
        // puts its own there; plugins add theirs beside it.
        const product = named(m.groups[0]);
        if (!product.name) break;
        if (/^wordpress$/i.test(product.name)) {
          if (!out.fingerprint) out.fingerprint = evidence.generator;
          add(out.facts, { kind: "core", name: "", version: product.version, evidence: evidence.generator });
          break;
        }
        add(out.facts, {
          kind: "plugin",
          name: slug(product.name),
          version: product.version,
          evidence: `${evidence.generator}, which names “${m.groups[0]}”`,
        });
        break;
      }
      case "feed":
      case "atom":
      case "core-asset":
        add(out.facts, {
          kind: "core",
          name: "",
          version: versionLike(m.groups[0]) ? m.groups[0] : undefined,
          evidence: evidence[m.pattern],
        });
        break;
      case "asset": {
        const name = m.groups[1].toLowerCase();
        if (!slugRe.test(name)) break;
        add(out.facts, {
          kind: m.groups[0].toLowerCase() === "themes" ? "theme" : "plugin",
          name,
          version: versionLike(m.groups[2]) ? m.groups[2] : undefined,
          evidence: `${evidence.asset}: ${trim(m.match)}`,
        });
        break;
      }
    }
  }
  // Nothing in the body was WordPress's, so neither is anything read from
  // it: another system's generator meta is not a WordPress plugin.
  if (!out.fingerprint) out.facts = [];
  return out;
}

/** named splits a generator's content into the product and its version. */
function named(content: string): { name: string; version?: string } {
  const text = content.trim();
  const cut = text.lastIndexOf(" ");
  if (cut > 0) {
    const tail = text.slice(cut + 1);
    if (versionLike(tail)) return { name: text.slice(0, cut).trim(), version: tail };
  }
  return { name: text };
}

/** slug turns a product's name into the shape a plugin directory has. */
function slug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
}

/** The WordPress fingerprint a response's headers carry, or "". */
export function fromHeaders(headers: { name: string; value: string }[]): string {
  for (const h of headers) {
    const name = h.name.toLowerCase();
    if (name === "x-pingback" && h.value.toLowerCase().indexOf("xmlrpc.php") >= 0) {
      return "the X-Pingback header, naming xmlrpc.php";
    }
    if (name === "link" && h.value.indexOf("api.w.org") >= 0) {
      return "a Link header advertising the REST API (api.w.org)";
    }
  }
  return "";
}

/** add appends a fact unless the same one is already there. */
export function add(facts: Fact[], f: Fact): void {
  for (const have of facts) {
    if (have.kind === f.kind && have.name === f.name && (have.version || "") === (f.version || "")) return;
  }
  facts.push(f);
}

function trim(s: string): string {
  const flat = s.replace(/\\\//g, "/");
  return flat.length > 120 ? flat.slice(0, 120) + "…" : flat;
}
