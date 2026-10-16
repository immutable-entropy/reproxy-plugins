// Recognising a Vue single-page app and its Vite build from what the
// browser already loaded: the page's HTML, and the module bundles it pulls
// in. Pure functions over text, so they test with no fixtures and the SDK
// calls (fetching maps, recording findings) stay in main.ts.
//
// A production Vite SPA's static HTML is almost empty — a mount element and
// a module script — and looks the same whatever framework built it, so Vue
// is confirmed from the strongest signal available: a Vue/Nuxt marker in
// the HTML, or (later, in main.ts) the bundle's own source map naming
// node_modules/vue. The HTML alone tells Vite from the hashed module
// bundles it preloads.

/** What a page's HTML gives away about its framework and build. */
export interface HtmlFacts {
  /** The HTML names Vue directly (a Vue or Nuxt marker). */
  vue: boolean;
  /** Nuxt, Vue's meta-framework, built this page. */
  nuxt: boolean;
  /** Vite (module scripts + preloads, or the dev client) built the assets. */
  vite: boolean;
  /** The markers that fired, for the finding's notes. */
  signals: string[];
  /** The asset references the page loads: scripts, preloads, stylesheets. */
  assets: Asset[];
}

export interface Asset {
  /** The href as written in the HTML (not yet resolved to an absolute URL). */
  ref: string;
  /** "module" (a JS entry whose map is worth fetching), "modulepreload", "style", or "preload". */
  kind: "module" | "modulepreload" | "style" | "preload";
}

// Vue- and Nuxt-specific markers. A plain client-rendered Vite+Vue app has
// none of these in its static HTML (it looks like any Vite app); Nuxt and
// server-rendered Vue do.
const VUE_MARKERS: [RegExp, string][] = [
  [/id=["']__nuxt["']/, "Nuxt mount element (#__nuxt)"],
  [/window\.__NUXT__/, "Nuxt state (window.__NUXT__)"],
  [/\/_nuxt\//, "Nuxt asset path (/_nuxt/)"],
  [/data-v-app\b/, "Vue 3 app root (data-v-app)"],
  [/\bdata-v-[0-9a-f]{6,10}\b/, "Vue scoped-style attribute (data-v-…)"],
  [/window\.__VUE__|__VUE_OPTIONS_API__|__VUE_PROD_DEVTOOLS__/, "Vue feature flag"],
];

const NUXT_MARKERS = /id=["']__nuxt["']|window\.__NUXT__|\/_nuxt\//;
// A dev server (vite dev) injects its client; a build preloads hashed modules.
const VITE_DEV = /\/@vite\/client|\/@vue\/|\/@id\/|\/node_modules\/\.vite\//;

/** Read a page's HTML (already decoded). max bounds how much is scanned. */
export function detectHtml(html: string, max = 2 << 20): HtmlFacts {
  const text = html.length > max ? html.slice(0, max) : html;
  const facts: HtmlFacts = { vue: false, nuxt: false, vite: false, signals: [], assets: [] };

  for (const [re, name] of VUE_MARKERS) {
    if (re.test(text)) {
      facts.vue = true;
      facts.signals.push(name);
    }
  }
  facts.nuxt = NUXT_MARKERS.test(text);

  facts.assets = assets(text);
  const moduleToAssets = facts.assets.some((a) => a.kind === "module" || a.kind === "modulepreload");
  if (VITE_DEV.test(text)) {
    facts.vite = true;
    facts.signals.push("Vite dev client");
  } else if (moduleToAssets) {
    facts.vite = true;
    facts.signals.push("ES module bundles with preloads (Vite-style build)");
  }
  return facts;
}

// A bounded scan of <script> and <link> tags. HTML is small for a SPA
// shell; a cap keeps a pathological page from costing more than it should.
const TAG = /<(script|link)\b([^>]*)>/gi;

function assets(html: string): Asset[] {
  const out: Asset[] = [];
  const seen = new Set<string>();
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = TAG.exec(html)) && count < 400) {
    count++;
    const tag = m[1].toLowerCase();
    const attrs = m[2];
    if (tag === "script") {
      if (!/type=["']module["']/.test(attrs)) continue;
      const src = attr(attrs, "src");
      push(out, seen, src, "module");
    } else {
      const rel = (attr(attrs, "rel") || "").toLowerCase();
      const href = attr(attrs, "href");
      if (rel.includes("modulepreload")) push(out, seen, href, "modulepreload");
      else if (rel.includes("stylesheet")) push(out, seen, href, "style");
      else if (rel.includes("preload") && /as=["']script["']/.test(attrs)) push(out, seen, href, "preload");
    }
  }
  return out;
}

function push(out: Asset[], seen: Set<string>, ref: string | undefined, kind: Asset["kind"]): void {
  if (!ref || seen.has(kind + " " + ref)) return;
  seen.add(kind + " " + ref);
  out.push({ ref, kind });
}

function attr(attrs: string, name: string): string | undefined {
  const m = new RegExp(name + `\\s*=\\s*["']([^"']+)["']`, "i").exec(attrs);
  return m ? m[1] : undefined;
}

/**
 * The source map a JavaScript bundle points at, if any: the last
 * `//# sourceMappingURL=…` in the file. An inline data: map is left alone
 * (nothing to fetch), and so is a map named with no value.
 */
export function sourceMapRef(js: string): string | undefined {
  const re = /[#@]\s*sourceMappingURL\s*=\s*([^\s'"]+)/g;
  let last: string | undefined;
  let m: RegExpExecArray | null;
  // The comment is at the end; scan only the tail to stay cheap on big bundles.
  const tail = js.length > 4096 ? js.slice(js.length - 4096) : js;
  while ((m = re.exec(tail))) last = m[1];
  if (!last || last.startsWith("data:")) return undefined;
  return last;
}
