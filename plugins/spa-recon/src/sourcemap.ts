// Reading a JavaScript source map (the Source Map v3 format a Vite/Rollup
// build writes beside each bundle). Pure functions over the parsed JSON.
//
// What a map gives an authorized tester, in order of value:
//
//   - that it is published at all: a production source map hands back the
//     readable, un-minified client source, which is a finding in itself;
//   - the application's own source files (its routes, components, API
//     clients), told from its dependencies by not living in node_modules —
//     the real map of the front end;
//   - the exact versions of the frameworks it was built with, which fall
//     out of the dependency paths a package manager writes
//     (node_modules/vue@3.4.2, .pnpm/nuxt@4.6.1_…).
//
// The reply is outside input, so every field is checked before it is used,
// and nothing is trusted to be the shape it should be.

import { frameworkForDep, frameworkForExt, versioned } from "./frameworks";

/** A source path and the original text the map carries for it, if any. */
export interface SourceFile {
  /** The path as written in the map. */
  path: string;
  /** The original source text (sourcesContent), or null when the map omits it. */
  content: string | null;
}

/** What a map held, once read. */
export interface SourceMap {
  /** The source paths, as written. */
  sources: string[];
  /** Each source path paired with its embedded content (null when absent). */
  files: SourceFile[];
  /** True when the map also carries the original source text. */
  hasContent: boolean;
}

/** Parse a map's JSON into what this plugin reads, or undefined if it isn't one. */
export function readSourceMap(json: unknown): SourceMap | undefined {
  if (!json || typeof json !== "object") return undefined;
  const o = json as Record<string, unknown>;
  // A v3 map has version 3 and a sources array. The mappings string is
  // what makes it a source map rather than, say, a web-app manifest.
  if (o.version !== 3 || !Array.isArray(o.sources) || typeof o.mappings !== "string") return undefined;
  // sourcesContent is index-aligned to sources, so the two are read together
  // to keep each path with its own text; a path with no string content
  // keeps a null, so reconstruction can report it as present but empty.
  const contents = Array.isArray(o.sourcesContent) ? o.sourcesContent : [];
  const sources: string[] = [];
  const files: SourceFile[] = [];
  for (let i = 0; i < o.sources.length; i++) {
    const s = o.sources[i];
    if (typeof s !== "string" || !s) continue;
    sources.push(s);
    const c = contents[i];
    files.push({ path: s, content: typeof c === "string" ? c : null });
  }
  if (sources.length === 0) return undefined;
  return { sources, files, hasContent: files.some((f) => f.content !== null && f.content.length > 0) };
}

/** An application source file (not a dependency), tidied for reading. */
export interface AppSource {
  /** The path as written in the map. */
  raw: string;
  /** The same with the build's leading "../" and virtual markers stripped. */
  tidy: string;
}

// Paths that are not the application's own code: dependencies, the bundler's
// virtual modules, and polyfills a build injects.
const NOT_APP = /(^|\/)node_modules\/|^\x00|^[a-z-]+:|(^|\/)virtual:|\/\.vite\/|(^|\/)vite\/|rollup|commonjsHelpers|modulepreload-polyfill/i;

/** Whether a source path is the application's own code, not a dependency. */
export function isAppSource(path: string): boolean {
  return !NOT_APP.test(path);
}

/**
 * The application's own source files, deduplicated, at most limit. These are
 * the paths worth showing a tester: the front end's real structure.
 */
export function appSources(map: SourceMap, limit = 300): AppSource[] {
  const out: AppSource[] = [];
  const seen = new Set<string>();
  for (const raw of map.sources) {
    if (NOT_APP.test(raw)) continue;
    const tidy = tidyPath(raw);
    if (!tidy || seen.has(tidy)) continue;
    seen.add(tidy);
    out.push({ raw, tidy });
    if (out.length >= limit) break;
  }
  return out;
}

/** A source path with the build's leading "../", "./" and query stripped. */
export function tidyPath(p: string): string {
  let s = p.replace(/^(?:\.\.\/)+/, "").replace(/^\.\//, "");
  // Vite writes some entries with a scheme-like prefix or query; keep the path.
  const q = s.indexOf("?");
  if (q >= 0) s = s.slice(0, q);
  return s.replace(/^\/+/, "");
}

/** A dependency and the version its path revealed. */
export interface Dep {
  name: string;
  version: string;
}

// A package in a dependency path, with the version a package manager wrote
// after it. pnpm appends a peer-dependency hash after the version with "_",
// which the version capture deliberately stops before.
const DEP = /node_modules\/(?:\.pnpm\/)?((?:@[a-z0-9][a-z0-9._-]*[+/])?[a-z0-9][a-z0-9._-]*)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)/g;

/**
 * The framework, build-tool and UI-kit versions a map's dependency paths
 * reveal. Which packages are worth reporting is frameworks.ts's `versioned`;
 * everything else in node_modules is noise.
 */
export function frameworkVersions(map: SourceMap): Dep[] {
  const found = new Map<string, string>();
  for (const raw of map.sources) {
    DEP.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = DEP.exec(raw))) {
      const name = normalizeName(m[1]);
      if (!versioned(name)) continue;
      if (!found.has(name)) found.set(name, m[2]);
    }
  }
  return [...found.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([name, version]) => ({ name, version }));
}

function normalizeName(n: string): string {
  // pnpm writes a scope as "@scope+name"; npm as "@scope/name".
  return n.startsWith("@") ? "@" + n.slice(1).replace("+", "/") : n;
}

/**
 * Every dependency a map's node_modules paths name, with its version,
 * deduplicated and sorted. frameworkVersions keeps only the frameworks worth
 * a rich note; this is the whole bill of materials, for recording each
 * dependency and its version as a finding (its source is not recovered, so
 * the finding is where that fact is kept).
 */
export function allDeps(map: SourceMap): Dep[] {
  const found = new Map<string, string>();
  for (const raw of map.sources) {
    DEP.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = DEP.exec(raw))) {
      const name = normalizeName(m[1]);
      if (!found.has(name)) found.set(name, m[2]);
    }
  }
  return [...found.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([name, version]) => ({ name, version }));
}

/**
 * The front-end framework a map reveals, as a framework id ("vue", "react",
 * "svelte", "angular"), or undefined. It is read from a framework dependency
 * in node_modules or an application source-file extension (.vue, .svelte).
 * This is how a client-rendered SPA — whose static HTML names nothing — is
 * confirmed and labelled.
 */
export function mapFramework(map: SourceMap): string | undefined {
  for (const raw of map.sources) {
    DEP.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = DEP.exec(raw))) {
      const id = frameworkForDep(normalizeName(m[1]));
      if (id) return id;
    }
  }
  for (const s of map.sources) {
    if (/node_modules/.test(s)) continue;
    const id = frameworkForExt(s);
    if (id) return id;
  }
  return undefined;
}
