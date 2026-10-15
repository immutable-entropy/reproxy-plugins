// active.ts: acquiring a plugin's or theme's version by asking for it.
//
// The rest of this plugin is passive: it reads only what the traffic already
// carried. These helpers are the exception, and the reason they live apart.
// When a plugin or theme is found but its version was never stated in the
// traffic (its assets carried no ?ver=, or carried the core version, which
// says nothing), WordPress still keeps the version in two well-known files:
//
//   - a plugin ships  wp-content/plugins/<slug>/readme.txt  with a line
//     "Stable tag: 5.3.1" — the version the directory publishes;
//   - a theme ships    wp-content/themes/<slug>/style.css   whose header
//     block carries "Version: 1.2".
//
// This is what wpscan does to pin a version down. Fetching those files is a
// request of our own, so main.ts only does it when the user turns active
// scanning on. These functions are pure: they say which files to try and
// read a version out of what comes back, so they test with no network.

import { versionLike } from "./fingerprint";

/** A file to request for a part, and how to read a version out of it. */
export interface Probe {
  url: string;
  read: (body: string) => string;
}

/** pluginProbes lists the files to try for a plugin, most telling first. */
export function pluginProbes(scheme: string, host: string, slug: string): Probe[] {
  const base = `${scheme}://${host}/wp-content/plugins/${slug}`;
  return [{ url: `${base}/readme.txt`, read: readmeVersion }];
}

/** themeProbes lists the files to try for a theme, most telling first. */
export function themeProbes(scheme: string, host: string, slug: string): Probe[] {
  const base = `${scheme}://${host}/wp-content/themes/${slug}`;
  return [
    { url: `${base}/style.css`, read: styleVersion },
    { url: `${base}/readme.txt`, read: readmeVersion },
  ];
}

/** The path of a probe URL, for a finding's notes (no scheme or host). */
export function probePath(url: string): string {
  const after = url.indexOf("://");
  const slash = after >= 0 ? url.indexOf("/", after + 3) : url.indexOf("/");
  return slash >= 0 ? url.slice(slash) : url;
}

// Only the head of a file is read: a readme or a style.css states its
// version in the first lines, and scanning megabytes in goja is wasteful.
const maxRead = 64 * 1024;

/**
 * readmeVersion reads the version a plugin or theme readme.txt publishes.
 * The WordPress.org format puts it on a "Stable tag:" line; a readme that
 * only carries a "Version:" header is read too.
 */
export function readmeVersion(body: string): string {
  const head = body.slice(0, maxRead);
  const stable = /(?:^|\n)[ \t]*stable tag:[ \t]*([^\r\n]{1,32})/i.exec(head);
  if (stable) {
    const v = stable[1].trim();
    if (versionLike(v)) return v;
  }
  return headerVersion(head);
}

/**
 * styleVersion reads the "Version:" header from a theme's style.css. The
 * header lives in the CSS comment block at the top of the file, each field
 * on its own line.
 */
export function styleVersion(body: string): string {
  return headerVersion(body.slice(0, maxRead));
}

/**
 * headerVersion reads a "Version: X" header line, as WordPress writes it in
 * file headers (optionally behind comment punctuation such as "*" or "#").
 */
function headerVersion(text: string): string {
  const m = /(?:^|\n)[ \t*#/]*version:[ \t]*([0-9][0-9a-z._-]{0,31})/i.exec(text);
  if (m) {
    const v = m[1].trim();
    if (versionLike(v)) return v;
  }
  return "";
}
