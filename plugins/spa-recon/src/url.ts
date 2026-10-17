// Resolving a reference as written in a page (a script src, a
// sourceMappingURL, a manifest path) against the URL it was written in.
// Enough of RFC 3986 for what a build emits: absolute, protocol-relative,
// root-relative and dot-relative references. There is no URL class in the
// plugin runtime, so this is done by hand.

/** Resolve ref against the absolute URL base; "" if it can't be made absolute. */
export function resolveUrl(base: string, ref: string): string {
  const r = (ref || "").trim();
  if (!r) return "";
  if (/^https?:\/\//i.test(r)) return r;
  if (/^[a-z][a-z0-9+.-]*:/i.test(r) && !r.startsWith("//")) return ""; // data:, blob:, mailto:, …

  const b = parse(base);
  if (!b) return "";
  if (r.startsWith("//")) return b.scheme + ":" + r;
  if (r.startsWith("/")) return b.scheme + "://" + b.authority + normalizePath(r);
  // Relative to the base's directory.
  const dir = b.path.slice(0, b.path.lastIndexOf("/") + 1) || "/";
  return b.scheme + "://" + b.authority + normalizePath(dir + r);
}

/** The directory URL a bundle sits in, for resolving a relative map ref. */
export function dirOf(url: string): string {
  const b = parse(url);
  if (!b) return url;
  const dir = b.path.slice(0, b.path.lastIndexOf("/") + 1) || "/";
  return b.scheme + "://" + b.authority + dir;
}

/** The scheme://authority of a URL, for probing manifest paths at its root. */
export function originOf(url: string): string {
  const b = parse(url);
  return b ? b.scheme + "://" + b.authority : "";
}

/**
 * The authority (host, with its port if any) of a URL, or "". This matches
 * capture's Flow.host, so a host seen in the HTML and the same host seen in
 * a bundle's source map compare equal.
 */
export function authorityOf(url: string): string {
  const b = parse(url);
  return b ? b.authority : "";
}

interface Parts {
  scheme: string;
  authority: string;
  path: string;
}

function parse(url: string): Parts | undefined {
  const m = /^(https?):\/\/([^/?#]+)([^?#]*)/i.exec(url || "");
  if (!m) return undefined;
  return { scheme: m[1].toLowerCase(), authority: m[2], path: m[3] || "/" };
}

/** Remove "." and ".." segments and the query/fragment of a path. */
function normalizePath(path: string): string {
  const [p] = path.split(/[?#]/);
  const out: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "..") out.pop();
    else if (seg !== "." && seg !== "") out.push(seg);
  }
  return "/" + out.join("/");
}
