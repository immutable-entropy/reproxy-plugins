// Where a link sits in an HTML page, which is what tells an organisation's
// own account from a link that happens to be on the page.
//
// A social or source link in the site's <header>, <footer> or <nav>, or
// carrying rel="me" (the indieweb way of claiming an account), is almost
// always the site's own. The same link deep in the body of an article or a
// comment may be a third party's or a visitor's. We can't parse the DOM in
// the runtime, so this reads the markup around the link by hand: cheap
// string work, and only ever for the handful of links that already
// classified (see links.ts), never for the whole page.

export interface Context {
  /** The nearest structural region the link sits in. */
  region: "header" | "footer" | "nav" | "body";
  /** The <a> carried rel="me": an explicit claim of the account. */
  relMe: boolean;
  /** The link is the site's own account, not one it merely mentions. */
  official: boolean;
}

/** The regions that mark a site's own chrome, innermost-looking first. */
const REGIONS: Context["region"][] = ["footer", "header", "nav"];

/** Characters that continue a host or path, so "twitter.com/acme" is not
 *  taken to match inside "twitter.com/acme/status/1". */
const PATH_CHAR = /[A-Za-z0-9/._~%+-]/;

/** locate finds needle where it is a whole host-and-path, not a prefix of a
 *  longer one. A trailing slash (the account's own URL written "…/acme/") is
 *  allowed; a further path segment is not. */
function locate(lower: string, needle: string): number {
  for (let from = 0; ; ) {
    const at = lower.indexOf(needle, from);
    if (at < 0) return -1;
    let end = at + needle.length;
    if (lower[end] === "/") end++; // an allowed trailing slash
    const next = lower[end];
    if (next === undefined || !PATH_CHAR.test(next)) return at;
    from = at + needle.length;
  }
}

/**
 * analyze reads the markup around the first occurrence of needle (a link's
 * host and path, lower cased) in lower, a lower-cased copy of the HTML. When
 * the link isn't found — a resolved or protocol-relative URL that isn't in
 * the source verbatim — it is treated as body content.
 */
export function analyze(lower: string, needle: string): Context {
  const idx = needle ? locate(lower, needle) : -1;
  if (idx < 0) return { region: "body", relMe: false, official: false };

  let region: Context["region"] = "body";
  for (const tag of REGIONS) {
    const open = lower.lastIndexOf("<" + tag, idx);
    if (open < 0) continue;
    const close = lower.indexOf("</" + tag, open);
    if (close < 0 || close > idx) {
      region = tag;
      break;
    }
  }

  // The <a …> tag the link is the href of: rel="me" is inside it.
  let relMe = false;
  const aStart = lower.lastIndexOf("<a ", idx);
  if (aStart >= 0) {
    const aEnd = lower.indexOf(">", aStart);
    if (aEnd > idx) relMe = /\brel\s*=\s*["'][^"']*\bme\b/.test(lower.slice(aStart, aEnd));
  }

  // A container that announces itself as social links also makes it the
  // site's own, even when it is not in the header or footer.
  const near = lower.slice(Math.max(0, idx - 400), idx);
  const social = /class\s*=\s*["'][^"']*\b(?:social|socials|social-links|social-media|follow-us|footer-social)\b/.test(near);

  return { region, relMe, official: region !== "body" || relMe || social };
}
