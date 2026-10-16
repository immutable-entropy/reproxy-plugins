import { describe, expect, it } from "reproxy/testing";
import { detectHtml, sourceMapRef } from "../src/detect";

describe("detectHtml", () => {
  it("recognises a Vite-built Vue SPA shell and its assets", () => {
    const html = `<!doctype html><html><head>
      <link rel="stylesheet" href="/assets/index-DItfvL25.css">
      <link rel="modulepreload" href="/assets/vendor-abc.js">
      <script type="module" crossorigin src="/assets/index-DPViepmO.js"></script>
    </head><body><div id="app" data-v-app></div></body></html>`;
    const f = detectHtml(html);
    expect(f.vite).toBe(true);
    expect(f.vue).toBe(true); // data-v-app
    // In document order.
    expect(f.assets.map((a) => `${a.kind} ${a.ref}`)).toEqual([
      "style /assets/index-DItfvL25.css",
      "modulepreload /assets/vendor-abc.js",
      "module /assets/index-DPViepmO.js",
    ]);
  });

  it("recognises Nuxt", () => {
    const html = `<html><body><div id="__nuxt"></div><script>window.__NUXT__={}</script>
      <script type="module" src="/_nuxt/entry.DVaTRCP8.js"></script></body></html>`;
    const f = detectHtml(html);
    expect(f.vue).toBe(true);
    expect(f.nuxt).toBe(true);
    expect(f.signals.join(";")).toContain("Nuxt");
  });

  it("recognises a Vite dev server", () => {
    const html = `<html><body><div id="app"></div>
      <script type="module" src="/@vite/client"></script>
      <script type="module" src="/src/main.ts"></script></body></html>`;
    const f = detectHtml(html);
    expect(f.vite).toBe(true);
    expect(f.signals.join(";")).toContain("dev client");
  });

  it("calls a Vite build without a Vue marker Vite-only, not Vue", () => {
    // A React+Vite shell looks like this: Vite, but nothing says Vue.
    const html = `<div id="root"></div><script type="module" src="/assets/index-xyz.js"></script>
      <link rel="modulepreload" href="/assets/chunk.js">`;
    const f = detectHtml(html);
    expect(f.vite).toBe(true);
    expect(f.vue).toBe(false);
  });

  it("finds nothing in a plain server-rendered page", () => {
    const f = detectHtml(`<html><body><h1>Hello</h1><script src="/jquery.js"></script></body></html>`);
    expect(f.vite).toBe(false);
    expect(f.vue).toBe(false);
    expect(f.assets).toEqual([]);
  });
});

describe("sourceMapRef", () => {
  it("reads the sourceMappingURL comment, ignoring an inline map", () => {
    expect(sourceMapRef("const a=1;\n//# sourceMappingURL=index-abc.js.map")).toBe("index-abc.js.map");
    expect(sourceMapRef("x//@ sourceMappingURL=../maps/app.js.map\n")).toBe("../maps/app.js.map");
    expect(sourceMapRef("code\n//# sourceMappingURL=data:application/json;base64,eyJ2")).toBeUndefined();
    expect(sourceMapRef("just code, no map")).toBeUndefined();
  });
});
