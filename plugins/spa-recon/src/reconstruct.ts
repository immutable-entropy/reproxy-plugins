// Reconstructing the original source files a source map embeds — what a
// tester means by "un-webpacking" a build.
//
// A Vite/webpack production map carries the original, un-minified source of
// every module in sourcesContent, index-aligned to sources. Recovering it is
// not the VLQ decoding the "mappings" field needs (that only maps positions
// back to lines): the text is already there, verbatim, so this is a plain
// walk that pairs each path with its content and tidies the path for
// reading. The point is to read the real source — its routes, its API
// clients, the URLs it calls — rather than the minified bundle.

import { isAppSource, tidyPath, type SourceMap } from "./sourcemap";

/** One recovered source file: a readable path and the original text. */
export interface RecoveredFile {
  /** The path, tidied (leading "../" and query stripped). */
  path: string;
  /** The original, un-minified source. */
  content: string;
  /** True for the application's own code, false for a dependency. */
  app: boolean;
}

/**
 * The source files a map actually carries text for, deduplicated by path and
 * capped at limit. A path present with no content is left out: there is
 * nothing to recover for it. Application files come before dependencies, so
 * a cap keeps the code worth reading.
 */
export function recoverFiles(map: SourceMap, limit = 5000): RecoveredFile[] {
  const app: RecoveredFile[] = [];
  const deps: RecoveredFile[] = [];
  const seen = new Set<string>();
  for (const f of map.files) {
    if (f.content === null || f.content.length === 0) continue;
    const path = tidyPath(f.path) || f.path;
    if (seen.has(path)) continue;
    seen.add(path);
    (isAppSource(f.path) ? app : deps).push({ path, content: f.content, app: isAppSource(f.path) });
  }
  return app.concat(deps).slice(0, limit);
}
