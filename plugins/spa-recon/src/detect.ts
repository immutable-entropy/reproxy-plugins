// Recognising a single-page app and its build from what the browser already
// loaded: the page's HTML, and the module bundles it pulls in. Pure
// functions over text, so they test with no fixtures and the SDK calls
// (fetching maps, recording findings) stay in main.ts.
//
// Which framework built the page comes from the table in frameworks.ts. A
// production SPA's static HTML is often a near-empty shell — a mount element
// and a module script — and looks much the same whatever framework built
// it, so a framework is confirmed from the strongest signal available: an
// HTML marker, or (later, in main.ts) the bundle's own source map naming the
// framework in node_modules. The HTML alone still tells a bundler build from
// the hashed modules it preloads.

import { detectFrameworks, type Detected } from "./frameworks";

/** What a page's HTML gives away about its framework and build. */
export interface HtmlFacts {
  /** The frameworks identified from the HTML, primary first. */
  frameworks: Detected[];
  /** A bundler build (module scripts + preloads, or a Vite dev client) made the assets. */
  bundled: boolean;
  /** Whether that build looks like Vite specifically (for manifest probing). */
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

// A dev server (vite dev) injects its client; a build preloads hashed modules.
const VITE_DEV = /\/@vite\/client|\/@vue\/|\/@id\/|\/node_modules\/\.vite\//;

/** Read a page's HTML (already decoded). max bounds how much is scanned. */
export function detectHtml(html: string, max = 2 << 20): HtmlFacts {
  const text = html.length > max ? html.slice(0, max) : html;
  const facts: HtmlFacts = { frameworks: [], bundled: false, vite: false, signals: [], assets: [] };

  facts.frameworks = detectFrameworks(text);
  for (const f of facts.frameworks) {
    for (const s of f.signals) facts.signals.push(`${f.name}: ${s}`);
  }

  facts.assets = assets(text);
  const moduleAssets = facts.assets.some((a) => a.kind === "module" || a.kind === "modulepreload");
  if (VITE_DEV.test(text)) {
    facts.bundled = true;
    facts.vite = true;
    facts.signals.push("Vite dev client");
  } else if (moduleAssets) {
    facts.bundled = true;
    // Module bundles with preloads are the Vite/Rollup build shape; a
    // build-manifest probe is worth a try. Next.js (/_next/) is also a
    // bundler build but keeps its own manifest, so it is not called Vite.
    facts.vite = !facts.frameworks.some((f) => f.id === "next");
    facts.signals.push("ES module bundles with preloads (bundler build)");
  }
  return facts;
}

/** Whether any framework was identified in the HTML. */
export function anyFramework(facts: HtmlFacts): boolean {
  return facts.frameworks.length > 0;
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
