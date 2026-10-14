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

describe("onEndpoint", () => {
  it("records the site, its core version, its plugins and its theme", async () => {
    const flow = mock.flow({
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html", "X-Pingback": "https://blog.test/xmlrpc.php" },
      responseBody: page,
    });
    expect(await mock.dispatch("endpoint.on_discovered", flow)).toBe(1);

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

  it("reads an endpoint core only discovered: the author archive the page linked to", async () => {
    await mock.dispatch("endpoint.on_discovered", {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: page,
    });
    const author = mock.endpoints().filter((e) => e.path === "/author/jdoe")[0];
    expect(author.visited).toBe(false);

    expect(await mock.dispatch("endpoint.on_discovered", author)).toBe(1);
    expect(byValue("jdoe (blog.test)")?.types).toEqual(["wordpress-user"]);
  });

  it("records what the REST API gives away", async () => {
    await mock.dispatch("endpoint.on_discovered", {
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
    await mock.dispatch("endpoint.on_discovered", {
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
    await mock.dispatch("endpoint.on_discovered", {
      url: "https://blog.test/wp-json/",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: JSON.stringify({ namespaces: ["woocommerce/v3"], author_name: "jane" }),
    });
    expect(values()).toEqual(["WordPress (blog.test)"]);
  });

  it("reads only the paths when reading responses is off", async () => {
    mock.settings({ read_pages: false });
    await mock.dispatch("endpoint.on_discovered", {
      url: "https://blog.test/wp-content/plugins/akismet/_inc/akismet.js?ver=5.3.1",
      responseHeaders: { "Content-Type": "application/javascript" },
      responseBody: "//",
    });
    expect(values()).toEqual(["WordPress (blog.test)", "akismet (blog.test)"]);
    expect(byValue("akismet (blog.test)")?.notes).toContain("No version was stated");
    expect(byValue("akismet (blog.test)")?.notes).not.toContain("version 5.3.1");
  });

  it("takes an asset's version from the request that fetched it", async () => {
    await mock.dispatch("endpoint.on_discovered", {
      url: "https://blog.test/wp-content/plugins/akismet/_inc/akismet.js?ver=5.3.1",
      responseHeaders: { "Content-Type": "application/javascript" },
      responseBody: "//",
    });
    expect(values()).toEqual(["WordPress (blog.test)", "akismet (blog.test)"]);
    expect(byValue("akismet (blog.test)")?.notes).toContain("version 5.3.1");
  });

  it("says nothing about a site that isn't WordPress", async () => {
    expect(
      await mock.dispatch("endpoint.on_discovered", {
        url: "https://shop.test/products/12",
        responseHeaders: { "Content-Type": "text/html" },
        responseBody: `<html><head><meta name="generator" content="Hugo"></head>
          <body><a href="/author/jdoe/">J Doe</a><script src="/static/app.js?ver=3"></script></body></html>`,
      }),
    ).toBe(1);
    expect(mock.findings()).toHaveLength(0);
  });

  it("keeps a plugin found twice over — assets and a REST namespace — to one finding", async () => {
    await mock.dispatch("endpoint.on_discovered", {
      url: "https://blog.test/wp-content/plugins/jetpack/jetpack.js?ver=16.4",
      responseHeaders: { "Content-Type": "application/javascript" },
      responseBody: "//",
    });
    await mock.dispatch("endpoint.on_discovered", {
      url: "https://blog.test/wp-json/",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: JSON.stringify({ namespaces: ["wp/v2", "jetpack/v4", "jetpack/v4/blaze"] }),
    });
    expect(values()).toEqual(["WordPress (blog.test)", "jetpack (blog.test)"]);
    const jetpack = byValue("jetpack (blog.test)");
    expect(jetpack?.notes).toContain("version 16.4");
    expect(jetpack?.notes).toContain("registers the namespace jetpack");
  });

  it("records each thing once, however often the endpoint comes round", async () => {
    const flow = mock.flow({
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: page,
    });
    const endpoint = mock.endpoint(flow);
    await mock.dispatch("endpoint.on_discovered", endpoint);
    const first = mock.findings().length;
    await mock.dispatch("endpoint.on_discovered", endpoint);
    await mock.dispatch("endpoint.on_updated", endpoint);
    expect(mock.findings()).toHaveLength(first);
  });

  it("keeps a plugin to one finding when its version turns up later", async () => {
    // The asset endpoint on its own: a slug, no version.
    await mock.dispatch("endpoint.on_discovered", {
      url: "https://blog.test/wp-content/plugins/akismet/_inc/akismet.js",
      responseHeaders: { "Content-Type": "application/javascript" },
      responseBody: "//",
    });
    expect(values()).toEqual(["WordPress (blog.test)", "akismet (blog.test)"]);

    // Then a page that states it.
    await mock.dispatch("endpoint.on_discovered", {
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
  it("is called for every endpoint put on the Map", async () => {
    expect(
      await mock.dispatch("endpoint.on_discovered", { url: "https://shop.test/products/12" }),
    ).toBe(1);
  });

  it("is called again only for the paths that keep saying something new", async () => {
    const rest = mock.endpoint({
      url: "https://blog.test/wp-json/wp/v2/users",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: "[]",
    });
    expect(await mock.dispatch("endpoint.on_updated", rest)).toBe(1);

    const other = mock.endpoint({ url: "https://blog.test/shop/", responseBody: "<html></html>" });
    expect(await mock.dispatch("endpoint.on_updated", other)).toBe(0);
  });

  it("never sends a request of its own", async () => {
    await mock.dispatch("endpoint.on_discovered", {
      url: "https://blog.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: page,
    });
    expect(mock.sent()).toHaveLength(0);
  });
});
