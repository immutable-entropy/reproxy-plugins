import { describe, expect, it } from "reproxy/testing";
import { appSources, frameworkVersions, readSourceMap } from "../src/sourcemap";

// A map shaped like a real Vite/pnpm build: the app's own files, framework
// dependencies with versions in their paths, a bundler virtual module, and
// a polyfill.
const map = {
  version: 3,
  file: "index-abc.js",
  mappings: "AAAA,SAAS",
  names: [],
  sources: [
    "../../src/main.ts",
    "../../src/App.vue",
    "../../src/router/index.ts",
    "../../src/api/client.ts",
    "../../node_modules/.pnpm/vue@3.4.21_typescript@5.4.5/node_modules/vue/dist/vue.runtime.esm-bundler.js",
    "../../node_modules/.pnpm/vue-router@4.3.0_vue@3.4.21/node_modules/vue-router/dist/vue-router.mjs",
    "../../node_modules/.pnpm/pinia@2.1.7_vue@3.4.21/node_modules/pinia/dist/pinia.mjs",
    "../../node_modules/@vueuse/core@10.9.0/index.mjs",
    "../../node_modules/left-pad@1.3.0/index.js",
    "\u0000virtual:/vite/preload-helper",
    "vite/modulepreload-polyfill",
  ],
  sourcesContent: ["import { createApp } from 'vue'", "", "", "", null, null, null, null, null, null, null],
};

describe("readSourceMap", () => {
  it("reads a v3 map, and rejects what isn't one", () => {
    const m = readSourceMap(map);
    expect(m).toBeDefined();
    expect(m!.sources.length).toBe(11);
    expect(m!.hasContent).toBe(true);

    expect(readSourceMap({ version: 3, sources: [] })).toBeUndefined(); // no mappings, no sources
    expect(readSourceMap({ version: 2, sources: ["a"], mappings: "" })).toBeUndefined();
    expect(readSourceMap({ name: "My App", icons: [] })).toBeUndefined(); // a web-app manifest
    expect(readSourceMap("<html>")).toBeUndefined();
  });

  it("keeps each path paired with its embedded content, aligned to the map", () => {
    const m = readSourceMap(map)!;
    expect(m.files.length).toBe(m.sources.length);
    expect(m.files[0]).toEqual({ path: "../../src/main.ts", content: "import { createApp } from 'vue'" });
    // A dependency the build kept the path for but not the content.
    expect(m.files[4].path).toContain("vue.runtime");
    expect(m.files[4].content).toBeNull();
  });
});

describe("appSources", () => {
  it("keeps the application's own files and drops dependencies and bundler noise", () => {
    const app = appSources(readSourceMap(map)!).map((s) => s.tidy);
    expect(app).toEqual(["src/main.ts", "src/App.vue", "src/router/index.ts", "src/api/client.ts"]);
  });

  it("honours the limit", () => {
    expect(appSources(readSourceMap(map)!, 2).length).toBe(2);
  });
});

describe("frameworkVersions", () => {
  it("reads framework and build versions from dependency paths, and ignores unrelated packages", () => {
    const deps = frameworkVersions(readSourceMap(map)!).map((d) => `${d.name}@${d.version}`);
    expect(deps).toEqual(["@vueuse/core@10.9.0", "pinia@2.1.7", "vue@3.4.21", "vue-router@4.3.0"]);
    expect(deps.some((d) => d.startsWith("left-pad"))).toBe(false);
  });

  it("stops the version before pnpm's peer-dependency suffix", () => {
    const m = readSourceMap({
      version: 3,
      mappings: "A",
      sources: ["x/node_modules/.pnpm/nuxt@4.6.1_cc75278574bf341e9ce37834970edd3e/node_modules/nuxt/dist/app.js"],
    })!;
    expect(frameworkVersions(m)).toEqual([{ name: "nuxt", version: "4.6.1" }]);
  });
});
