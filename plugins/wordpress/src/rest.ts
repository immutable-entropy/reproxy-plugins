// Reading WordPress's REST API out of replies that have already been made.
//
// The API answers a few routes without authentication, and what they say is
// an inventory: the root lists every namespace registered, which is one per
// plugin that offers an API; wp/v2/users names accounts; an oEmbed reply
// names the author of the post it describes. On a misconfigured site
// wp/v2/plugins and wp/v2/themes answer too, and those hold the versions
// outright.

import { add, type Fact } from "./fingerprint";

/** The namespaces core registers itself: anything else is a plugin's. */
const coreNamespaces = [
  "wp/v2",
  "wp-site-health/v1",
  "wp-block-editor/v1",
  "wp-abilities/v1",
  "oembed/1.0",
  "batch/v1",
];

/** The most namespaces of one vendor named in a fact's evidence. */
const maxShown = 4;

/**
 * The REST route a request was for: the part after /wp-json, or the
 * rest_route parameter when the API is reached that way. "" when it isn't a
 * REST request at all.
 */
export function routeOf(path: string, query: string): string {
  if (path === "/wp-json" || path.indexOf("/wp-json/") === 0) {
    const route = path.slice("/wp-json".length);
    return route === "" ? "/" : route;
  }
  const m = /(?:^|[&;])rest_route=([^&;#]*)/.exec(query);
  if (!m) return "";
  const route = m[1].replace(/%2f/gi, "/").replace(/\+/g, " ");
  return route === "" ? "/" : route;
}

/**
 * The facts a REST reply states. route is what routeOf gave, body the parsed
 * JSON; both the route and the shape are checked, so a reply that isn't what
 * its route suggests is left alone.
 */
export function readRest(route: string, body: unknown): Fact[] {
  const out: Fact[] = [];
  if (!route || body === null || typeof body !== "object") return out;

  if (!Array.isArray(body)) {
    const obj = body as Record<string, unknown>;

    // The root: every namespace registered, core's own among them. One
    // plugin often registers several (Jetpack registers six), so they are
    // grouped by the first segment — which is usually the plugin's own name,
    // and so lines up with what its assets say.
    if (Array.isArray(obj.namespaces)) {
      const byVendor: Record<string, string[]> = {};
      const order: string[] = [];
      for (const ns of obj.namespaces) {
        if (typeof ns !== "string" || !ns || coreNamespaces.indexOf(ns) >= 0) continue;
        const vendor = ns.split("/")[0].toLowerCase();
        if (!vendor) continue;
        if (!byVendor[vendor]) {
          byVendor[vendor] = [];
          order.push(vendor);
        }
        byVendor[vendor].push(ns);
      }
      for (const vendor of order) {
        const list = byVendor[vendor];
        const shown = list.slice(0, maxShown).join(", ") + (list.length > maxShown ? ", …" : "");
        add(out, { kind: "rest-namespace", name: vendor, evidence: `the REST API root, which lists ${shown}` });
      }
    }
    // An oEmbed reply names the post's author.
    if (typeof obj.author_name === "string" && obj.author_name) {
      add(out, { kind: "user", name: obj.author_name, evidence: `an oEmbed reply's author_name` });
    }
    return out;
  }

  for (const item of body) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) continue;
    const row = item as Record<string, unknown>;
    const version = typeof row.version === "string" ? row.version : undefined;

    // wp/v2/plugins: "plugin" is the file, "akismet/akismet".
    if (typeof row.plugin === "string" && row.plugin) {
      const slug = row.plugin.split("/")[0].toLowerCase();
      if (slug) add(out, { kind: "plugin", name: slug, version, evidence: "the REST route wp/v2/plugins, which lists what is installed" });
      continue;
    }
    // wp/v2/themes: "stylesheet" is the theme's directory.
    if (typeof row.stylesheet === "string" && row.stylesheet) {
      const slug = row.stylesheet.split("/")[0].toLowerCase();
      if (slug) add(out, { kind: "theme", name: slug, version, evidence: "the REST route wp/v2/themes, which lists what is installed" });
      continue;
    }
    // wp/v2/users: the slug is the account's name in URLs.
    if (route.indexOf("/users") >= 0) {
      const name = typeof row.slug === "string" && row.slug ? row.slug : typeof row.name === "string" ? row.name : "";
      if (!name) continue;
      const display = typeof row.name === "string" ? row.name : "";
      const id = typeof row.id === "number" ? row.id : undefined;
      add(out, {
        kind: "user",
        name,
        evidence: `the REST route ${route}${id ? `, as user ${id}` : ""}${display && display !== name ? ` (${display})` : ""}`,
      });
    }
  }
  return out;
}
