import { beforeEach, describe, expect, it, mock } from "reproxy/testing";
import type { Finding } from "reproxy";
import { init } from "../main";

// The plugin keeps what it has already reported for as long as it runs, so
// each test starts it afresh — exactly what a reload does in the app.
beforeEach(() => init({ hook: "plugin.on_load", reason: "reload", settings: {} }));

const page = `<!doctype html><html><head>
  <meta name="generator" content="WordPress 6.4.3" />
  <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2" />
  <script src="/wp-content/plugins/akismet/_inc/akismet.js?ver=5.3.1"></script>
  <script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=6.4.3"></script>
  <script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.4.3"></script>
  </head><body><a href="/author/jdoe/">J Doe</a></body></html>`;

function values(): string[] {
  return mock.findings().map((f) => f.value).sort();
}

function byValue(value: string): Finding | undefined {
  return mock.findings().filter((f) => f.value === value)[0];
}

describe("onUrl", () => {
  it("records the site, its core version, its plugins and its theme", async () => {
    const flow = mock.flow({
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html", "X-Pingback": "https://blog.test/xmlrpc.php" },
      responseBody: page,
    });
    expect(await mock.dispatch("url.on_created", flow)).toBe(1);

    expect(values()).toEqual([
      "WordPress (blog.test)",
      "akismet (blog.test)",
      "contact-form-7 (blog.test)",
      "twentytwentyfour (blog.test)",
    ]);

    const site = byValue("WordPress (blog.test)");
    expect(site?.types).toEqual(["wordpress"]);
    expect(site?.notes).toContain("Core version 6.4.3");
    expect(site?.links[0].flowId).toBe(flow.id);

    // contact-form-7's assets carry the core version, so its own is unknown.
    expect(byValue("contact-form-7 (blog.test)")?.notes).toContain("which is the core version");

    const akismet = byValue("akismet (blog.test)");
    expect(akismet?.types).toEqual(["wordpress-plugin"]);
    expect(akismet?.notes).toContain("version 5.3.1");
    expect(akismet?.fields).toContain({ key: "version", value: "5.3.1" });

    const theme = byValue("twentytwentyfour (blog.test)");
    expect(theme?.types).toEqual(["wordpress-theme"]);
    expect(theme?.notes).toContain("version 1.2");
  });

  it("reads a URL core only discovered: the author archive the page linked to", async () => {
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: page,
    });
    const author = mock.entities().filter((e) => e.type === "url" && e.path === "/author/jdoe")[0];
    expect(author.visited).toBe(false);

    expect(await mock.dispatch("url.on_created", author)).toBe(1);
    expect(byValue("jdoe (blog.test)")?.types).toEqual(["wordpress-user"]);
  });

  it("records what the REST API gives away", async () => {
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/wp-json/",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: JSON.stringify({
        name: "Blog",
        namespaces: ["oembed/1.0", "wp/v2", "woocommerce/v3", "yoast/v1"],
      }),
    });
    expect(values()).toEqual(["WordPress (blog.test)", "woocommerce (blog.test)", "yoast (blog.test)"]);
    expect(byValue("yoast (blog.test)")?.types).toEqual(["wordpress-plugin"]);
    expect(byValue("yoast (blog.test)")?.notes).toContain("registers the namespace yoast");
  });

  it("records the accounts the users route lists", async () => {
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/wp-json/wp/v2/users",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: JSON.stringify([{ id: 1, name: "Jane Doe", slug: "jane" }]),
    });
    expect(values()).toEqual(["WordPress (blog.test)", "jane (blog.test)"]);
    expect(byValue("jane (blog.test)")?.fields).toEqual([
      { key: "host", value: "blog.test" },
      { key: "account", value: "jane" },
    ]);
  });

  it("leaves users and namespaces out when the user turns them off", async () => {
    mock.settings({ record_users: false, record_rest_namespaces: false });
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/wp-json/",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: JSON.stringify({ namespaces: ["woocommerce/v3"], author_name: "jane" }),
    });
    expect(values()).toEqual(["WordPress (blog.test)"]);
  });

  it("reads only the paths when reading responses is off", async () => {
    mock.settings({ read_pages: false });
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/wp-content/plugins/akismet/_inc/akismet.js?ver=5.3.1",
      responseHeaders: { "Content-Type": "application/javascript" },
      responseBody: "//",
    });
    expect(values()).toEqual(["WordPress (blog.test)", "akismet (blog.test)"]);
    expect(byValue("akismet (blog.test)")?.notes).toContain("No version was stated");
    expect(byValue("akismet (blog.test)")?.notes).not.toContain("version 5.3.1");
  });

  it("takes an asset's version from the request that fetched it", async () => {
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/wp-content/plugins/akismet/_inc/akismet.js?ver=5.3.1",
      responseHeaders: { "Content-Type": "application/javascript" },
      responseBody: "//",
    });
    expect(values()).toEqual(["WordPress (blog.test)", "akismet (blog.test)"]);
    expect(byValue("akismet (blog.test)")?.notes).toContain("version 5.3.1");
  });

  it("says nothing about a site that isn't WordPress", async () => {
    expect(
      await mock.dispatch("url.on_created", {
        url: "https://shop.test/products/12",
        responseHeaders: { "Content-Type": "text/html" },
        responseBody: `<html><head><meta name="generator" content="Hugo"></head>
          <body><a href="/author/jdoe/">J Doe</a><script src="/static/app.js?ver=3"></script></body></html>`,
      }),
    ).toBe(1);
    expect(mock.findings()).toHaveLength(0);
  });

  it("keeps a plugin found twice over — assets and a REST namespace — to one finding", async () => {
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/wp-content/plugins/jetpack/jetpack.js?ver=16.4",
      responseHeaders: { "Content-Type": "application/javascript" },
      responseBody: "//",
    });
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/wp-json/",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: JSON.stringify({ namespaces: ["wp/v2", "jetpack/v4", "jetpack/v4/blaze"] }),
    });
    expect(values()).toEqual(["WordPress (blog.test)", "jetpack (blog.test)"]);
    const jetpack = byValue("jetpack (blog.test)");
    expect(jetpack?.notes).toContain("version 16.4");
    expect(jetpack?.notes).toContain("registers the namespace jetpack");
  });

  it("records each thing once, however often the URL comes round", async () => {
    const flow = mock.flow({
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: page,
    });
    const url = mock.entity(flow);
    await mock.dispatch("url.on_created", url);
    const first = mock.findings().length;
    await mock.dispatch("url.on_created", url);
    await mock.dispatch("url.on_updated", url);
    expect(mock.findings()).toHaveLength(first);
  });

  it("keeps a plugin to one finding when its version turns up later", async () => {
    // The asset URL on its own: a slug, no version.
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/wp-content/plugins/akismet/_inc/akismet.js",
      responseHeaders: { "Content-Type": "application/javascript" },
      responseBody: "//",
    });
    expect(values()).toEqual(["WordPress (blog.test)", "akismet (blog.test)"]);

    // Then a page that states it.
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: page,
    });
    expect(mock.findings().filter((f) => f.value === "akismet (blog.test)")).toHaveLength(1);
    const akismet = byValue("akismet (blog.test)");
    expect(akismet?.notes).toContain("No version was stated");
    expect(akismet?.notes).toContain("version 5.3.1");
    expect(akismet?.links.length).toBeGreaterThan(1);
  });
});

describe("the hooks it is on", () => {
  it("is called for every URL put in the Explorer", async () => {
    // A flow that was answered: core maps a URL from the request that
    // reached something, not from one nothing answered, so a fixture
    // without a response never gets as far as the Explorer.
    expect(
      await mock.dispatch("url.on_created", { url: "https://shop.test/products/12", status: 200 }),
    ).toBe(1);
  });

  it("is called again only for the paths that keep saying something new", async () => {
    const rest = mock.entity({
      url: "https://blog.test/wp-json/wp/v2/users",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: "[]",
    });
    expect(await mock.dispatch("url.on_updated", rest)).toBe(1);

    const other = mock.entity({ url: "https://blog.test/shop/", responseBody: "<html></html>" });
    expect(await mock.dispatch("url.on_updated", other)).toBe(0);
  });

  it("never sends a request of its own", async () => {
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: page,
    });
    expect(mock.sent()).toHaveLength(0);
  });
});

describe("active version scanning", () => {
  // On this page contact-form-7's assets carry ?ver=6.4.3 — the core
  // version — so the traffic never states the plugin's own version.
  const cfPage = `<!doctype html><html><head>
    <meta name="generator" content="WordPress 6.4.3" />
    <script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=6.4.3"></script>
    <script src="/wp-content/plugins/akismet/_inc/akismet.js?ver=5.3.1"></script>
    </head><body></body></html>`;

  it("asks for a plugin's readme.txt when the traffic gave no version", async () => {
    mock.settings({ active_version_scan: true });
    mock.respond("/wp-content/plugins/contact-form-7/readme\\.txt", {
      status: 200,
      headers: { "Content-Type": "text/plain" },
      body: "=== Contact Form 7 ===\nStable tag: 5.9.2\n",
    });

    await mock.dispatch("url.on_created", {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: cfPage,
    });

    const urls = mock.sent().map((r) => r.url);
    expect(urls).toContain("https://blog.test/wp-content/plugins/contact-form-7/readme.txt");
    // A plugin whose version the traffic did state is not asked for.
    expect(urls.some((u) => u.indexOf("akismet") >= 0)).toBe(false);

    const cf = byValue("contact-form-7 (blog.test)");
    expect(cf?.notes).toContain("version 5.9.2");
    expect(cf?.notes).toContain("active request");
    expect(cf?.fields).toContain({ key: "version", value: "5.9.2" });
  });

  it("asks for a theme's style.css", async () => {
    mock.settings({ active_version_scan: true });
    mock.respond("/wp-content/themes/storefront/style\\.css", {
      status: 200,
      headers: { "Content-Type": "text/css" },
      body: "/*\nTheme Name: Storefront\nVersion: 3.9.1\n*/\n",
    });

    await mock.dispatch("url.on_created", {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: `<meta name="generator" content="WordPress 6.4.3" />
        <link rel="stylesheet" href="/wp-content/themes/storefront/style.css?ver=6.4.3" />`,
    });

    expect(mock.sent().map((r) => r.url)).toContain("https://blog.test/wp-content/themes/storefront/style.css");
    expect(byValue("storefront (blog.test)")?.notes).toContain("version 3.9.1");
  });

  it("sends nothing while the setting is off", async () => {
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: cfPage,
    });
    expect(mock.sent()).toHaveLength(0);
    expect(byValue("contact-form-7 (blog.test)")?.notes).toContain("which is the core version");
  });

  it("records no version when the file isn't there (404) or doesn't state one", async () => {
    mock.settings({ active_version_scan: true });
    // No mock.respond rule: the harness answers 404.
    await mock.dispatch("url.on_created", {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: cfPage,
    });
    expect(mock.sent()).toHaveLength(1); // it tried
    const cf = byValue("contact-form-7 (blog.test)");
    expect(cf?.notes).toContain("which is the core version");
    expect(cf?.notes).not.toContain("active request");
  });

  it("probes a plugin only once across repeated events", async () => {
    mock.settings({ active_version_scan: true });
    mock.respond("/contact-form-7/readme\\.txt", { status: 200, body: "Stable tag: 5.9.2\n" });
    const ep = {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: cfPage,
    };
    await mock.dispatch("url.on_created", ep);
    await mock.dispatch("url.on_updated", ep);
    expect(mock.sent().filter((r) => r.url.indexOf("contact-form-7") >= 0)).toHaveLength(1);
  });

  it("and only once across a reload, because the engagement remembers", async () => {
    mock.settings({ active_version_scan: true });
    mock.respond("/contact-form-7/readme\\.txt", { status: 200, body: "Stable tag: 5.9.2\n" });
    const ep = {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: cfPage,
    };
    await mock.dispatch("url.on_created", ep);
    expect(mock.sent()).toHaveLength(1);

    // A reload clears the session's state; what the engagement remembers
    // being asked is what has to stop the site being asked again.
    init({ hook: "plugin.on_load", reason: "reload", settings: {} });
    await mock.dispatch("url.on_created", ep);
    expect(mock.sent()).toHaveLength(1);
    // The version it learned the first time is still known, so the part is
    // not reported as one whose version was never stated.
    expect(byValue("contact-form-7 (blog.test)")?.notes).toContain("version 5.9.2");
  });

  it("does not ask again for a part whose files said nothing", async () => {
    mock.settings({ active_version_scan: true });
    const ep = {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: cfPage,
    };
    // No mock.respond rule: the harness answers 404, and that is an answer.
    await mock.dispatch("url.on_created", ep);
    expect(mock.sent()).toHaveLength(1);

    init({ hook: "plugin.on_load", reason: "reload", settings: {} });
    await mock.dispatch("url.on_created", ep);
    expect(mock.sent()).toHaveLength(1);
  });

});
