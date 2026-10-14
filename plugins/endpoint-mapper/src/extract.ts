// extract finds the URLs a response body refers to, each with a note of
// where it was found. It only reads; main.ts decides what goes on the map.

import { text } from "reproxy";

export interface Found {
  url: string;
  /** Where it was found: "html", "json:$.links[0].href", "js:fetch", "robots", "sitemap", "openapi:GET /users/{id}". */
  detail: string;
}

export interface Options {
  max: number;
  openapi: boolean;
}

export function extract(body: string, base: string, contentType: string, opts: Options): Found[] {
  const out: Found[] = [];
  const seen: Record<string, boolean> = {};
  const add = (raw: string, detail: string) => {
    const url = resolve(raw, base);
    if (!url || seen[url] || out.length >= opts.max) return;
    seen[url] = true;
    out.push({ url, detail });
  };
  const path = base.replace(/^[a-z]+:\/\/[^/]+/i, "").split("?")[0];

  if (path === "/robots.txt") {
    for (const u of robots(body)) add(u.url, u.detail);
  }
  if (/xml/.test(contentType) || /\.xml$/.test(path)) {
    for (const u of sitemap(body)) add(u, "sitemap");
  }
  if (/json/.test(contentType)) {
    let doc: unknown;
    try {
      doc = JSON.parse(body);
    } catch {
      doc = undefined;
    }
    if (doc !== undefined) {
      if (opts.openapi) for (const u of openapi(doc, base)) add(u.url, u.detail);
      walkJSON(doc, "$", (value, at) => {
        if (looksLikeURL(value)) add(value, "json:" + at);
      });
    }
  }
  if (/javascript|html/.test(contentType)) {
    for (const c of scriptCalls(body)) add(c.url, "js:" + c.via);
  }
  // Last, Go's general sweep: HTML attributes, quoted paths, absolute URLs.
  for (const u of text.urls(body, base, contentType || "text/plain", opts.max)) add(u, kind(contentType));
  return out;
}

function kind(contentType: string): string {
  if (/html/.test(contentType)) return "html";
  if (/json/.test(contentType)) return "json";
  if (/javascript/.test(contentType)) return "js";
  return "text";
}

/** resolve makes a URL absolute against base; null for anything not http(s). */
export function resolve(raw: string, base: string): string | null {
  raw = raw.trim();
  if (!raw || /^(?:mailto|javascript|data|tel|about|blob):/i.test(raw)) return null;
  const m = /^([a-z][a-z0-9+.-]*:)?(\/\/[^/?#]*)?([^?#]*)(\?[^#]*)?/i.exec(raw);
  if (!m) return null;
  const b = /^(https?:)\/\/([^/?#]+)([^?#]*)/i.exec(base);
  if (!b) return null;
  let scheme = m[1] ? m[1].toLowerCase() : b[1].toLowerCase();
  if (scheme !== "http:" && scheme !== "https:") return null;
  const host = m[2] ? m[2].slice(2) : b[2];
  if (!host) return null;
  let p = m[3] || "";
  if (!m[2] && !m[1] && p && p[0] !== "/") {
    p = b[3].replace(/[^/]*$/, "") + p; // relative to the base's directory
  }
  if (!p) p = m[2] || m[1] ? "/" : b[3];
  return scheme + "//" + host.toLowerCase() + normalise(p) + (m[4] || "");
}

function normalise(path: string): string {
  const out: string[] = [];
  for (const seg of path.split("/")) {
    if (seg === "..") out.pop();
    else if (seg !== "." && seg !== "") out.push(seg);
  }
  return "/" + out.join("/") + (path.endsWith("/") && out.length ? "/" : "");
}

/** looksLikeURL: an absolute http(s) URL, or a root-relative path with a letter in it. */
export function looksLikeURL(v: string): boolean {
  if (v.length > 2048) return false;
  if (/^https?:\/\/[^\s/]+/i.test(v)) return !/\s/.test(v);
  return /^\/[A-Za-z0-9_\-.~%/{}]*[A-Za-z][A-Za-z0-9_\-.~%/{}]*$/.test(v) && !v.startsWith("//");
}

/** walkJSON calls fn with every string in a JSON document and its JSONPath. */
export function walkJSON(v: unknown, at: string, fn: (value: string, at: string) => void, depth = 0): void {
  if (depth > 32) return;
  if (typeof v === "string") fn(v, at);
  else if (Array.isArray(v)) v.forEach((x, i) => walkJSON(x, `${at}[${i}]`, fn, depth + 1));
  else if (v && typeof v === "object") {
    for (const k of Object.keys(v as object)) {
      const child = /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(k) ? `${at}.${k}` : `${at}[${JSON.stringify(k)}]`;
      walkJSON((v as Record<string, unknown>)[k], child, fn, depth + 1);
    }
  }
}

/** scriptCalls finds the URLs scripts request: fetch, axios, XMLHttpRequest.open, $.ajax-style url fields. */
export function scriptCalls(body: string): { url: string; via: string }[] {
  const q = `["'\`]([^"'\`\\s]{1,1000})["'\`]`;
  const found = text.scan(body, [
    { name: "fetch", pattern: `\\bfetch\\(\\s*${q}` },
    { name: "axios", pattern: `\\baxios(?:\\.(?:get|post|put|patch|delete|head|options|request))?\\(\\s*${q}` },
    { name: "xhr", pattern: `\\.open\\(\\s*["'][A-Za-z]+["']\\s*,\\s*${q}` },
    { name: "url", pattern: `\\burl\\s*:\\s*${q}` },
  ]);
  return found
    .map((m) => ({ url: m.groups[0], via: m.pattern }))
    .filter((c) => c.url.startsWith("/") || /^https?:\/\//i.test(c.url) || c.url.startsWith("./"));
}

/** robots reads Allow, Disallow and Sitemap lines. Wildcards are cut at the first *. */
export function robots(body: string): Found[] {
  const out: Found[] = [];
  for (const line of body.split(/\r?\n/)) {
    const m = /^\s*(allow|disallow|sitemap)\s*:\s*(\S+)/i.exec(line);
    if (!m) continue;
    let p = m[2];
    const star = p.indexOf("*");
    if (star >= 0) p = p.slice(0, star);
    p = p.replace(/\$$/, "");
    if (p && p !== "/") out.push({ url: p, detail: "robots:" + m[1].toLowerCase() });
  }
  return out;
}

/** sitemap reads the <loc> entries of a sitemap or sitemap index. */
export function sitemap(body: string): string[] {
  return text.scan(body, [`(?i)<loc>\\s*([^<\\s]+)\\s*</loc>`]).map((m) => m.groups[0].replace(/&amp;/g, "&"));
}

/** openapi lists the operations of an OpenAPI 3 or Swagger 2 document. */
export function openapi(doc: unknown, base: string): Found[] {
  const d = doc as Record<string, unknown>;
  if (!d || typeof d !== "object" || (!d.openapi && !d.swagger) || typeof d.paths !== "object" || !d.paths) return [];
  let root = "";
  const servers = d.servers as { url?: string }[] | undefined;
  if (Array.isArray(servers) && servers[0] && typeof servers[0].url === "string") root = servers[0].url;
  else if (typeof d.host === "string") {
    const schemes = d.schemes as string[] | undefined;
    root = `${schemes && schemes[0] ? schemes[0] : base.split(":")[0]}://${d.host}${typeof d.basePath === "string" ? d.basePath : ""}`;
  } else if (typeof d.basePath === "string") root = d.basePath;
  const prefix = (resolve(root || "/", base) || base).replace(/\/$/, "");

  const out: Found[] = [];
  for (const p of Object.keys(d.paths as object)) {
    const item = (d.paths as Record<string, Record<string, unknown>>)[p] || {};
    const methods = Object.keys(item).filter((k) => /^(get|put|post|delete|options|head|patch|trace)$/i.test(k));
    const detail = "openapi:" + (methods.length ? methods.map((x) => x.toUpperCase()).join(",") : "?") + " " + p;
    out.push({ url: prefix + (p.startsWith("/") ? p : "/" + p), detail });
  }
  return out;
}
