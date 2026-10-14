import { describe, it, expect } from "reproxy/testing";
import { fromHeaders, fromPath, looksWordPress, read, versionLike, versionOf, type Fact } from "../src/fingerprint";

function pick(facts: Fact[], kind: string, name: string): Fact | undefined {
  return facts.filter((f) => f.kind === kind && f.name === name)[0];
}

describe("looksWordPress", () => {
  it("knows the paths only WordPress serves", () => {
    expect(looksWordPress("/wp-content/themes/x/style.css")).toBe("/wp-content/");
    expect(looksWordPress("/wp-json/wp/v2/users")).toBe("/wp-json");
    expect(looksWordPress("/?rest_route=/wp/v2/users")).toBe("rest_route=");
    expect(looksWordPress("/WP-LOGIN.PHP")).toBe("/wp-login.php");
  });

  it("says nothing about anything else", () => {
    expect(looksWordPress("/products/12")).toBe("");
    expect(looksWordPress("/static/js/app.js")).toBe("");
  });
});

describe("fromPath", () => {
  it("reads a plugin slug out of an asset path", () => {
    const facts = fromPath("/wp-content/plugins/akismet/_inc/akismet.js");
    expect(facts).toHaveLength(1);
    expect(facts[0].kind).toBe("plugin");
    expect(facts[0].name).toBe("akismet");
    expect(facts[0].version).toBeUndefined();
  });

  it("takes the version from the query when it has one", () => {
    const facts = fromPath("/wp-content/themes/twentytwentyfour/style.css", "1.2");
    expect(facts[0].kind).toBe("theme");
    expect(facts[0].name).toBe("twentytwentyfour");
    expect(facts[0].version).toBe("1.2");
    expect(facts[0].evidence).toContain("?ver=1.2");
  });

  it("counts mu-plugins as plugins, and lower-cases the slug", () => {
    expect(fromPath("/wp-content/mu-plugins/Loader/load.php")[0].kind).toBe("plugin");
    expect(fromPath("/wp-content/mu-plugins/Loader/load.php")[0].name).toBe("loader");
  });

  it("reads an account out of an author archive", () => {
    const facts = fromPath("/author/jdoe/");
    expect(facts).toHaveLength(1);
    expect(facts[0].kind).toBe("user");
    expect(facts[0].name).toBe("jdoe");
  });

  it("leaves a templated segment alone", () => {
    expect(fromPath("/wp-content/plugins/{id}/x.js")).toHaveLength(0);
    expect(fromPath("/author/{id}")).toHaveLength(0);
    expect(fromPath("/products/12")).toHaveLength(0);
  });
});

describe("versionOf", () => {
  it("reads ver= out of a query", () => {
    expect(versionOf("ver=6.4.3")).toBe("6.4.3");
    expect(versionOf("a=1&ver=5.3.1&b=2")).toBe("5.3.1");
    expect(versionOf("minver=9&a=1")).toBe("");
    expect(versionOf("")).toBe("");
  });

  it("turns away a value that isn't a version", () => {
    expect(versionOf("ver=<script>")).toBe("");
  });
});

describe("versionLike", () => {
  it("accepts a version", () => {
    expect(versionLike("6.4.3")).toBe(true);
    expect(versionLike("1.2")).toBe(true);
    expect(versionLike("12")).toBe(true);
    expect(versionLike("7.2-alpha-64347")).toBe(true);
    expect(versionLike("2.0rc1")).toBe(true);
  });

  // wordpress.org itself serves both of these as ?ver=.
  it("turns away a cache-buster", () => {
    expect(versionLike("1781196525")).toBe(false);
    expect(versionLike("c98b5143585c3e9f06b27f6a917b65c84643cefc")).toBe(false);
    expect(versionLike("5381c0a3642be76565c7-20240308")).toBe(false);
    expect(versionLike("20240308")).toBe(false);
    expect(versionLike("")).toBe(false);
  });
});

describe("read", () => {
  const page = `<!doctype html><html><head>
    <meta name="generator" content="WordPress 6.4.3" />
    <link rel="https://api.w.org/" href="https://blog.test/wp-json/" />
    <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2" />
    <script src="/wp-content/plugins/akismet/_inc/akismet.js?ver=5.3.1"></script>
    <script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=6.4.3"></script>
    <script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.4.3"></script>
    </head><body><a href="/wp-login.php">Log in</a></body></html>`;

  it("reads the core version, the plugins and the theme", () => {
    const r = read(page);
    expect(r.fingerprint).toBe("the page's generator meta tag");
    expect(pick(r.facts, "core", "")?.version).toBe("6.4.3");
    expect(pick(r.facts, "plugin", "akismet")?.version).toBe("5.3.1");
    expect(pick(r.facts, "plugin", "contact-form-7")?.version).toBe("6.4.3");
    expect(pick(r.facts, "theme", "twentytwentyfour")?.version).toBe("1.2");
    expect(pick(r.facts, "plugin", "twentytwentyfour")).toBeUndefined();
  });

  it("reads a generator meta whose attributes are the other way round", () => {
    const r = read(`<meta content="WordPress 6.5" name="generator">`);
    expect(pick(r.facts, "core", "")?.version).toBe("6.5");
  });

  it("reads the version a feed states", () => {
    const r = read(`<rss><channel><generator>https://wordpress.org/?v=6.4.3</generator></channel></rss>`);
    expect(r.fingerprint).toContain("feed");
    expect(pick(r.facts, "core", "")?.version).toBe("6.4.3");
  });

  it("reads an Atom feed's generator", () => {
    const r = read(`<generator uri="https://wordpress.org/" version="6.2.1">WordPress</generator>`);
    expect(pick(r.facts, "core", "")?.version).toBe("6.2.1");
  });

  it("reads asset URLs that a JSON body has escaped", () => {
    const r = read(`{"content":"<img src=\\"\\/wp-content\\/plugins\\/woocommerce\\/assets\\/i.png?ver=8.4.0\\">"}`);
    expect(pick(r.facts, "plugin", "woocommerce")?.version).toBe("8.4.0");
  });

  it("recognises a site with no version anywhere", () => {
    const r = read(`<html><head><meta name="generator" content="WordPress"></head></html>`);
    expect(r.fingerprint).toBeTruthy();
    expect(pick(r.facts, "core", "")).toBeDefined();
    expect(pick(r.facts, "core", "")?.version).toBeUndefined();
  });

  it("doesn't take a cache-busting ?ver= for a version", () => {
    const r = read(`<script src="/wp-content/mu-plugins/pub-sync/b/view.js?ver=1781196525"></script>
      <link href="/wp-content/themes/wporg-news-2021/style.css?ver=c98b5143585c3e9f06b27f6a917b65c8">`);
    expect(pick(r.facts, "plugin", "pub-sync")).toBeDefined();
    expect(pick(r.facts, "plugin", "pub-sync")?.version).toBeUndefined();
    expect(pick(r.facts, "theme", "wporg-news-2021")?.version).toBeUndefined();
  });

  it("reads the plugin a second generator meta names", () => {
    const r = read(`<meta name="generator" content="WordPress 7.2-alpha-64347" />
      <meta name="generator" content="Seriously Simple Podcasting 3.17.0" />`);
    expect(pick(r.facts, "core", "")?.version).toBe("7.2-alpha-64347");
    const found = pick(r.facts, "plugin", "seriously-simple-podcasting");
    expect(found?.version).toBe("3.17.0");
    expect(found?.evidence).toContain("Seriously Simple Podcasting");
  });

  it("says nothing about a page that isn't WordPress", () => {
    const r = read(`<html><head><meta name="generator" content="Hugo 0.120"></head>
      <body><script src="/static/app.js?ver=3"></script></body></html>`);
    expect(r.fingerprint).toBe("");
    expect(r.facts).toHaveLength(0);
  });

  it("holds the same fact once", () => {
    const r = read(`<a href="/wp-content/plugins/akismet/a.js?ver=5.3"></a>
      <a href="/wp-content/plugins/akismet/b.js?ver=5.3"></a>`);
    expect(r.facts).toHaveLength(1);
  });
});

describe("fromHeaders", () => {
  it("recognises the pingback and REST headers", () => {
    expect(fromHeaders([{ name: "X-Pingback", value: "https://blog.test/xmlrpc.php" }])).toContain("X-Pingback");
    expect(fromHeaders([{ name: "link", value: '<https://blog.test/wp-json/>; rel="https://api.w.org/"' }])).toContain("Link");
    expect(fromHeaders([{ name: "Server", value: "nginx" }])).toBe("");
  });
});
