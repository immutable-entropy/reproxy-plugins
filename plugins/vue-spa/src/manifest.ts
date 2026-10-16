// Reading Vite's build manifest (manifest.json, or .vite/manifest.json on
// Vite 5+). It maps each source entry to the hashed files a build emitted,
// so when it is served it lists the application's whole built front end:
// every chunk, stylesheet and asset, named.
//
// Its shape is an object whose values are per-chunk records carrying a
// "file". A progressive-web-app manifest (also manifest.json) is a
// different thing entirely — top-level name, icons, start_url — so the
// validator here accepts a file only when it reads as a build manifest, and
// a PWA manifest yields nothing rather than a false finding.

/** What a Vite manifest listed. */
export interface ViteManifest {
  /** The built file paths it names: chunks, their CSS and their assets. */
  files: string[];
  /** The source paths of its entry points (isEntry), for the notes. */
  entries: string[];
}

/** Read a manifest's JSON, or undefined when it isn't a Vite build manifest. */
export function readViteManifest(json: unknown): ViteManifest | undefined {
  if (!json || typeof json !== "object" || Array.isArray(json)) return undefined;
  const o = json as Record<string, unknown>;
  // A PWA manifest has these at the top level and no chunk records.
  if (typeof o.name === "string" && (o.icons !== undefined || o.start_url !== undefined)) return undefined;

  const files = new Set<string>();
  const entries: string[] = [];
  let chunks = 0;
  for (const key of Object.keys(o)) {
    const rec = o[key];
    if (!rec || typeof rec !== "object" || Array.isArray(rec)) return undefined;
    const r = rec as Record<string, unknown>;
    if (typeof r.file !== "string" || !r.file) return undefined; // not a Vite manifest
    chunks++;
    files.add(r.file);
    addList(files, r.css);
    addList(files, r.assets);
    if (r.isEntry === true) entries.push(typeof r.src === "string" ? r.src : key);
  }
  if (chunks === 0) return undefined;
  return { files: [...files], entries };
}

function addList(into: Set<string>, v: unknown): void {
  if (!Array.isArray(v)) return;
  for (const x of v) if (typeof x === "string" && x) into.add(x);
}

/** The usual places a Vite build manifest is served, best first. */
export const MANIFEST_PATHS = ["/.vite/manifest.json", "/manifest.json", "/assets/.vite/manifest.json", "/assets/manifest.json"];
