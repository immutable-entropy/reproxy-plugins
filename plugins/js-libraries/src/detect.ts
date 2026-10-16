// Finding library versions in a script: in its URL, and in its text.

import { text } from "reproxy";
import { cdnjsNames, libraries, libraryOf, V } from "./signatures";

export interface Detection {
  /** The npm package. */
  npm: string;
  version: string;
  /** How it was found, for the finding's link: "URL (cdnjs.cloudflare.com)", "file name", "script text". */
  how: string;
  /** True when it was found in the script's text rather than its URL. */
  inBody: boolean;
}

const version = new RegExp(`^${V}$`);

/** File names a library is published under, longest first so "jquery-ui" wins over "jquery". */
const fileNames: [string, string][] = libraries
  .flatMap((l) => (l.files ?? []).map((f): [string, string] => [f, l.npm]))
  .sort((a, b) => b[0].length - a[0].length);
const dirNames: [string, string][] = libraries.flatMap((l) => (l.dirs ?? []).map((d): [string, string] => [d, l.npm]));

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/-]/g, "\\$&");
}

// jquery-3.5.1.min.js, jquery.validate-1.19.js, bootstrap.4.6.0.js…
const fileRe = new RegExp(
  `/(${fileNames.map((f) => escape(f[0])).join("|")})[-.@]${V}(?:[.-](?:min|slim|pack|prod|production|umd|bundle))*\\.m?js$`,
  "i",
);
// /vendor/bootstrap/4.6.0/js/bootstrap.min.js
const dirRe = new RegExp(`/(${dirNames.map((d) => escape(d[0])).join("|")})/v?${V}/`, "i");
// cdn.jsdelivr.net/npm/<package>@<version>/, unpkg.com/<package>@<version>/
const npmPathRe = new RegExp(`^/(?:npm/)?((?:@[a-z0-9][\\w.-]*/)?[a-z0-9][\\w.-]*)@${V}(?:/|$)`, "i");
// cdnjs.cloudflare.com and ajax.googleapis.com: /ajax/libs/<name>/<version>/
const ajaxLibsRe = new RegExp(`^/ajax/libs/([\\w.-]+)/${V}/`, "i");
// cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js
const datatablesRe = new RegExp(`^/${V}/js/jquery\\.dataTables`, "i");

/** The versions a script's URL names. host is lower case; path has no query. */
export function fromUrl(host: string, path: string): Detection[] {
  const out: Detection[] = [];
  const add = (npm: string, raw: string, how: string) => {
    // A file name's suffixes can pass for a pre-release tag:
    // react-16.14.0-production.min.js is 16.14.0.
    const v = raw.replace(/[.-](?:min|slim|pack|prod|production|development|umd|bundle)(?:[.-].*)?$/i, "");
    if (version.test(v) && !out.some((d) => d.npm === npm && d.version === v)) out.push({ npm, version: v, how, inBody: false });
  };
  let m: RegExpExecArray | null;
  if (host === "cdn.jsdelivr.net" || host === "unpkg.com") {
    // Only jsDelivr's /npm/ tree holds npm packages (/gh/ is GitHub).
    if ((host === "unpkg.com" || path.startsWith("/npm/")) && (m = npmPathRe.exec(path))) {
      add(m[1].toLowerCase(), m[2], `URL (${host})`);
    }
  }
  if ((m = ajaxLibsRe.exec(path))) {
    const name = m[1].toLowerCase();
    add(cdnjsNames[name] ?? name, m[2], `URL (${host})`);
  }
  if (host === "cdn.datatables.net" && (m = datatablesRe.exec(path))) add("datatables.net", m[1], "URL (cdn.datatables.net)");
  if ((m = fileRe.exec(path))) {
    const npm = fileNames.find((f) => f[0] === m![1].toLowerCase())?.[1];
    if (npm) add(npm, m[2], "file name");
  }
  if ((m = dirRe.exec(path))) {
    const npm = dirNames.find((d) => d[0] === m![1].toLowerCase())?.[1];
    if (npm) add(npm, m[2], "URL path");
  }
  return out;
}

/**
 * The versions a script's text gives away. Each rule's pattern runs only
 * when its needle is in the text, so a script with no library in it costs
 * a few substring searches.
 */
export function fromBody(body: string): Detection[] {
  const patterns: { name: string; pattern: string }[] = [];
  for (const lib of libraries) {
    for (const rule of lib.content ?? []) {
      if (body.indexOf(rule.needle) >= 0) patterns.push({ name: lib.npm, pattern: rule.pattern });
    }
  }
  if (patterns.length === 0) return [];
  const out: Detection[] = [];
  for (const m of text.scan(body, patterns, 50)) {
    const v = m.groups.filter((g) => g).join(".");
    if (!v || !version.test(v) || !libraryOf(m.pattern)) continue;
    if (!out.some((d) => d.npm === m.pattern && d.version === v)) {
      out.push({ npm: m.pattern, version: v, how: "script text", inBody: true });
    }
  }
  return out;
}

/** True when a version is complete enough to look up: three numbers, and any pre-release tag. */
export function exact(v: string): boolean {
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?$/.test(v);
}
