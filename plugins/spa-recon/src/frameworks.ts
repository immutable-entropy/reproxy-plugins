// The front-end frameworks this plugin recognises, as a table so adding one
// is a row rather than new code. Each is known three independent ways, any
// of which is enough:
//
//   - a marker in the page's HTML (strongest for a server-rendered or
//     meta-framework app);
//   - a dependency named in a source map's node_modules paths (what
//     confirms a client-rendered SPA, whose HTML is a bare shell);
//   - an application source-file extension (.vue, .svelte).
//
// A meta-framework (Nuxt, Next, SvelteKit) carries its base library (Vue,
// React, Svelte) through `base`, so a Nuxt detection also means Vue.

export interface Framework {
  /** Stable id: "vue", "react", "svelte", "angular", "nuxt", … */
  id: string;
  /** Human name for findings: "Vue.js", "Next.js". */
  name: string;
  /** For a meta-framework, the id of the library it is built on. */
  base?: string;
  /** HTML markers that identify it: a regex and what it means. */
  markers: [RegExp, string][];
  /** node_modules package names that confirm it: exact, or a prefix ending "/". */
  deps: string[];
  /** Application source-file extensions that confirm it. */
  exts: string[];
}

export const FRAMEWORKS: Framework[] = [
  {
    id: "vue",
    name: "Vue.js",
    markers: [
      [/data-v-app\b/, "Vue 3 app root (data-v-app)"],
      [/\bdata-v-[0-9a-f]{6,10}\b/, "Vue scoped-style attribute (data-v-…)"],
      [/window\.__VUE__|__VUE_OPTIONS_API__|__VUE_PROD_DEVTOOLS__/, "Vue feature flag"],
    ],
    deps: ["vue", "@vue/", "vue-router", "pinia", "vuex", "vue-i18n", "@vueuse/"],
    exts: [".vue"],
  },
  {
    id: "nuxt",
    name: "Nuxt",
    base: "vue",
    markers: [
      [/id=["']__nuxt["']/, "Nuxt mount element (#__nuxt)"],
      [/window\.__NUXT__/, "Nuxt state (window.__NUXT__)"],
      [/\/_nuxt\//, "Nuxt asset path (/_nuxt/)"],
    ],
    deps: ["nuxt", "@nuxt/"],
    exts: [],
  },
  {
    id: "react",
    name: "React",
    // A client-rendered React app's HTML is a bare <div id="root"></div>,
    // indistinguishable from any other framework, so these are the few
    // honest markers; the source map is what usually confirms React.
    markers: [
      [/\bdata-reactroot\b/, "React server-rendered root (data-reactroot)"],
      [/__REACT_DEVTOOLS_GLOBAL_HOOK__/, "React DevTools hook"],
    ],
    deps: ["react", "react-dom", "scheduler", "@remix-run/"],
    exts: [],
  },
  {
    id: "next",
    name: "Next.js",
    base: "react",
    markers: [
      [/id=["']__next["']/, "Next.js mount element (#__next)"],
      [/id=["']__NEXT_DATA__["']/, "Next.js data script (__NEXT_DATA__)"],
      [/\/_next\//, "Next.js asset path (/_next/)"],
    ],
    deps: ["next"],
    exts: [],
  },
  {
    id: "svelte",
    name: "Svelte",
    markers: [[/\bsvelte-[0-9a-z]{4,}\b/, "Svelte scoped class (svelte-…)"]],
    deps: ["svelte"],
    exts: [".svelte"],
  },
  {
    id: "sveltekit",
    name: "SvelteKit",
    base: "svelte",
    markers: [
      [/__sveltekit[_/]/, "SvelteKit runtime (__sveltekit)"],
      [/data-sveltekit-/, "SvelteKit attribute (data-sveltekit-…)"],
      [/\/_app\/immutable\//, "SvelteKit asset path (/_app/immutable/)"],
    ],
    deps: ["@sveltejs/kit", "@sveltejs/"],
    exts: [],
  },
  {
    id: "angular",
    name: "Angular",
    markers: [
      [/\bng-version=["'][^"']+["']/, "Angular version marker (ng-version)"],
      [/<app-root[\s/>]/, "Angular root element (<app-root>)"],
      [/_nghost-|_ngcontent-/, "Angular view-encapsulation attribute"],
    ],
    deps: ["@angular/"],
    exts: [],
  },
];

/** A framework identified in a page, with the markers that fired. */
export interface Detected {
  id: string;
  name: string;
  /** The base library's id, for a meta-framework. */
  base?: string;
  signals: string[];
}

const byID = new Map(FRAMEWORKS.map((f) => [f.id, f]));

/**
 * The frameworks whose HTML markers appear in text, primary first: a
 * meta-framework (Nuxt) comes before the base (Vue) it implies, and its base
 * is added even if the base's own markers didn't fire. Within a tier, table
 * order wins.
 */
export function detectFrameworks(text: string): Detected[] {
  const hits = new Map<string, Detected>();
  for (const f of FRAMEWORKS) {
    const signals: string[] = [];
    for (const [re, label] of f.markers) {
      if (re.test(text)) signals.push(label);
    }
    if (signals.length > 0) hits.set(f.id, { id: f.id, name: f.name, base: f.base, signals });
  }
  // A meta-framework implies its base library.
  for (const d of [...hits.values()]) {
    if (d.base && !hits.has(d.base)) {
      const b = byID.get(d.base)!;
      hits.set(b.id, { id: b.id, name: b.name, signals: [`implied by ${d.name}`] });
    }
  }
  // Order: meta-frameworks first (they are the more specific finding).
  return [...hits.values()].sort((a, b) => rank(a) - rank(b));
}

function rank(d: Detected): number {
  const i = FRAMEWORKS.findIndex((f) => f.id === d.id);
  return (d.base ? 0 : 1000) + i; // metas (have a base) ahead of bases
}

function matchesDep(pkg: string, deps: string[]): boolean {
  return deps.some((d) => (d.endsWith("/") ? pkg.startsWith(d) : pkg === d || pkg.startsWith(d + "-")));
}

/** The framework id a dependency package belongs to, or undefined. */
export function frameworkForDep(pkg: string): string | undefined {
  for (const f of FRAMEWORKS) {
    if (matchesDep(pkg, f.deps)) return f.base ?? f.id;
  }
  return undefined;
}

/** The framework id an application source path points to (by extension), or undefined. */
export function frameworkForExt(path: string): string | undefined {
  for (const f of FRAMEWORKS) {
    if (f.exts.some((e) => path.endsWith(e) || path.includes(e + "?"))) return f.base ?? f.id;
  }
  return undefined;
}

// Build tools and UI kits worth reporting a version for, beyond the
// frameworks themselves: knowing the exact build or component-library
// version is as useful to a tester as the framework's.
const EXTRAS = [
  "vite", "@vitejs/", "rollup", "@rollup/", "webpack", "esbuild", "@angular-devkit/", "@angular/cli",
  "vuetify", "element-plus", "@element-plus/", "quasar", "naive-ui", "primevue", "ant-design-vue",
  "@mui/", "@chakra-ui/", "@mantine/", "antd", "bootstrap", "@ionic/", "vue-demi",
];

/** Whether a dependency is worth a version finding: a framework, build tool or UI kit. */
export function versioned(pkg: string): boolean {
  return frameworkForDep(pkg) !== undefined || matchesDep(pkg, EXTRAS);
}

/** The display name for a framework id (falls back to the id). */
export function nameOf(id: string): string {
  return byID.get(id)?.name ?? id;
}

/**
 * A label for a detected primary framework: the meta-framework naming its
 * base, e.g. "Nuxt (Vue.js)", or just the name for a base library.
 */
export function label(d: Detected): string {
  if (d.base) return `${d.name} (${nameOf(d.base)})`;
  return d.name;
}
