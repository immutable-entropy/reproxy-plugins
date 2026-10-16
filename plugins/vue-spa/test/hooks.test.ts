import { beforeEach, describe, expect, it, mock } from "reproxy/testing";
import { entities, storage, targets } from "reproxy";
import { idle, inspectHtml, inspectScript, load, setRequestGap } from "../main";

beforeEach(async () => {
  load();
  setRequestGap(0);
  await idle();
});

// A valid Vite source map naming Vue, the app's own files, and a URL in its
// original source.
const sourceMap = JSON.stringify({
  version: 3,
  file: "index-DPViepmO.js",
  mappings: "AAAA",
  names: [],
  sources: [
    "../../src/main.ts",
    "../../src/views/Login.vue",
    "../../node_modules/.pnpm/vue@3.4.21_typescript@5.4.5/node_modules/vue/dist/vue.runtime.esm-bundler.js",
    "../../node_modules/.pnpm/vue-router@4.3.0/node_modules/vue-router/dist/vue-router.mjs",
  ],
  sourcesContent: ["const api = 'https://api.app.test/v1'; fetch(api + '/me')", "", null, null],
});

const viteManifest = JSON.stringify({
  "index.html": { file: "assets/index-DPViepmO.js", src: "index.html", isEntry: true, css: ["assets/index-abc.css"] },
  "src/views/About.vue": { file: "assets/About-xyz.js", src: "src/views/About.vue", isEntry: true },
});

const nuxtHtml = `<!doctype html><html><head>
  <link rel="modulepreload" href="/assets/vendor.js">
  <script type="module" crossorigin src="/assets/index-DPViepmO.js"></script>
</head><body><div id="__nuxt"></div><script>window.__NUXT__={}</script></body></html>`;

function flow(partial: Record<string, unknown>): Record<string, unknown> {
  const t = targets.list().find((x) => x.value === "app.test");
  const url = String(partial.url);
  return { targetId: url.startsWith("https://app.test/") && t ? t.id : "", ...partial };
}

function js(url: string, body: string) {
  return flow({ url, responseHeaders: { "Content-Type": "application/javascript" }, responseBody: body });
}
function html(url: string, body: string) {
  return flow({ url, responseHeaders: { "Content-Type": "text/html" }, responseBody: body });
}
function reply(pattern: string, body: string, status = 200, ct = "application/json") {
  mock.respond(pattern, { status, headers: { "Content-Type": ct }, body });
}

describe("inspectHtml on an in-scope Vue/Vite app", () => {
  it("records the SPA, fetches the map and manifest, and fills the Explorer", async () => {
    mock.target("domain", "app.test");
    reply("/\\.vite/manifest\\.json$", viteManifest);
    reply("index-DPViepmO\\.js\\.map$", sourceMap);

    expect(await mock.dispatch("traffic.on_response_received", html("https://app.test/", nuxtHtml))).toBe(1);
    await idle();

    const found = mock.findings();
    const byType = (t: string) => found.filter((f) => f.types.includes(t)).map((f) => f.value);
    expect(byType("vue-spa")).toEqual(["Vue single-page app on app.test"]);
    expect(byType("build-manifest")).toEqual(["https://app.test/.vite/manifest.json"]);
    expect(byType("source-map")).toEqual(["https://app.test/assets/index-DPViepmO.js.map"]);
    // Versions came out of the map's dependency paths.
    expect(byType("tech-version").sort()).toEqual(["vue 3.4.21", "vue-router 4.3.0"]);

    const spa = found.find((f) => f.types.includes("vue-spa"))!;
    expect(spa.hidden).toBe(false);
    expect(Object.fromEntries(spa.fields.map((x) => [x.key, x.value])).framework).toBe("Nuxt (Vue)");

    const sm = found.find((f) => f.types.includes("source-map"))!;
    expect(sm.notes).toContain("src/views/Login.vue");
    expect(Object.fromEntries(sm.fields.map((x) => [x.key, x.value])).application_files).toBe("2");

    const sent = mock.sent().map((s) => s.url);
    expect(sent).toContain("https://app.test/.vite/manifest.json");
    expect(sent).toContain("https://app.test/assets/index-DPViepmO.js.map");

    const urls = mock.entities().filter((e) => e.type === "url").map((e) => e.key);
    // From the HTML, the manifest, and a URL inside the map's source.
    expect(urls.some((u) => u.includes("/assets/index-DPViepmO.js"))).toBe(true);
    expect(urls.some((u) => u.includes("/assets/About-xyz.js"))).toBe(true);
    expect(urls.some((u) => u.includes("api.app.test"))).toBe(true);
  });

  it("probes the manifest once per origin and fetches each map once", async () => {
    mock.target("domain", "app.test");
    reply("/\\.vite/manifest\\.json$", viteManifest);
    reply("index-DPViepmO\\.js\\.map$", sourceMap);
    for (let i = 0; i < 3; i++) {
      await mock.dispatch("traffic.on_response_received", html(`https://app.test/page${i}`, nuxtHtml));
      await idle();
    }
    const sent = mock.sent().map((s) => s.url);
    expect(sent.filter((u) => u.endsWith("manifest.json"))).toHaveLength(1);
    // Two module-ish assets (vendor + index) → two maps, each fetched once
    // across the three pages, not six.
    expect(sent.filter((u) => u.endsWith(".js.map")).sort()).toEqual([
      "https://app.test/assets/index-DPViepmO.js.map",
      "https://app.test/assets/vendor.js.map",
    ]);
  });

  it("does nothing active when both fetching settings are off", async () => {
    mock.target("domain", "app.test");
    mock.settings({ fetch_source_maps: false, probe_vite_manifest: false });
    await mock.dispatch("traffic.on_response_received", html("https://app.test/", nuxtHtml));
    await idle();
    expect(mock.sent()).toHaveLength(0);
    expect(mock.findings().map((f) => f.types[0])).toEqual(["vue-spa"]); // still detected, passively
  });

  it("records the SPA once when both the HTML and the map confirm it, even on a non-standard port", async () => {
    mock.target("ip", "127.0.0.1");
    reply("index-DPViepmO\\.js\\.map$", sourceMap);
    const f = {
      url: "http://127.0.0.1:18090/",
      targetId: targets.list()[0].id,
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: nuxtHtml,
    };
    await mock.dispatch("traffic.on_response_received", f);
    await idle();
    // flow.host is "127.0.0.1:18090"; the map is fetched from the same
    // authority, so it must not be recorded as a second SPA.
    expect(mock.findings().filter((x) => x.types.includes("vue-spa")).map((x) => x.value)).toEqual([
      "Vue single-page app on 127.0.0.1:18090",
    ]);
  });

  it("is not called for a page that is neither Vue nor Vite", async () => {
    mock.target("domain", "app.test");
    await mock.dispatch("traffic.on_response_received", html("https://app.test/", "<html><body><h1>plain</h1></body></html>"));
    await idle();
    expect(mock.findings()).toHaveLength(0);
    expect(mock.sent()).toHaveLength(0);
  });
});

describe("manifest validation", () => {
  it("doesn't mistake a progressive-web-app manifest for a build manifest", async () => {
    mock.target("domain", "app.test");
    reply("/manifest\\.json$", JSON.stringify({ name: "App", start_url: "/", icons: [{ src: "/i.png" }] }));
    // .vite/manifest.json and the rest 404 by default.
    await mock.dispatch("traffic.on_response_received", html("https://app.test/", nuxtHtml));
    await idle();
    expect(mock.findings().filter((f) => f.types.includes("build-manifest"))).toHaveLength(0);
  });
});

describe("inspectScript", () => {
  it("follows a bundle's sourceMappingURL and confirms a client-rendered Vue SPA from the map", async () => {
    mock.target("domain", "app.test");
    reply("app-xyz\\.js\\.map$", sourceMap);
    // The bundle names its map; the HTML shell named no framework, so the
    // SPA is confirmed from the map alone.
    await mock.dispatch("traffic.on_response_received", js("https://app.test/assets/app-xyz.js", "const x=1;\n//# sourceMappingURL=app-xyz.js.map"));
    await idle();
    expect(mock.sent().map((s) => s.url)).toEqual(["https://app.test/assets/app-xyz.js.map"]);
    const spa = mock.findings().find((f) => f.types.includes("vue-spa"));
    expect(spa?.value).toBe("Vue single-page app on app.test");
    expect(spa?.notes).toContain("confirmed from the source map");
  });

  it("ignores a bundle with no map reference", async () => {
    mock.target("domain", "app.test");
    await mock.dispatch("traffic.on_response_received", js("https://app.test/assets/app.js", "console.log(1)"));
    await idle();
    expect(mock.sent()).toHaveLength(0);
  });
});
