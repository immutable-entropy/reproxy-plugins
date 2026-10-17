import { describe, expect, it } from "reproxy/testing";
import { anyFramework, detectHtml, sourceMapRef } from "../src/detect";

function ids(html: string): string[] {
  return detectHtml(html).frameworks.map((f) => f.id);
}

describe("detectHtml framework detection", () => {
  it("recognises a Vite-built Vue SPA shell and its assets", () => {
    const html = `<!doctype html><html><head>
      <link rel="stylesheet" href="/assets/index-DItfvL25.css">
      <link rel="modulepreload" href="/assets/vendor-abc.js">
      <script type="module" crossorigin src="/assets/index-DPViepmO.js"></script>
    </head><body><div id="app" data-v-app></div></body></html>`;
    const f = detectHtml(html);
    expect(f.vite).toBe(true);
    expect(f.bundled).toBe(true);
    expect(f.frameworks.map((x) => x.id)).toEqual(["vue"]);
    // In document order.
    expect(f.assets.map((a) => `${a.kind} ${a.ref}`)).toEqual([
      "style /assets/index-DItfvL25.css",
      "modulepreload /assets/vendor-abc.js",
      "module /assets/index-DPViepmO.js",
    ]);
  });

  it("recognises Nuxt, with Vue as its base, Nuxt first", () => {
    const html = `<html><body><div id="__nuxt"></div><script>window.__NUXT__={}</script>
      <script type="module" src="/_nuxt/entry.DVaTRCP8.js"></script></body></html>`;
    const f = detectHtml(html);
    expect(f.frameworks.map((x) => x.id)).toEqual(["nuxt", "vue"]);
    expect(f.signals.join(";")).toContain("Nuxt");
  });

  it("recognises Next.js, with React as its base", () => {
    const html = `<div id="__next"></div><script id="__NEXT_DATA__" type="application/json">{}</script>
      <script src="/_next/static/chunks/main.js"></script>`;
    expect(ids(html)).toEqual(["next", "react"]);
  });

  it("recognises SvelteKit, with Svelte as its base", () => {
    const html = `<div style="display:contents">
      <script>__sveltekit_1a2b3c = {}</script>
      <link href="/_app/immutable/entry/start.js" rel="modulepreload"></div>`;
    expect(ids(html)).toEqual(["sveltekit", "svelte"]);
  });

  it("recognises Angular", () => {
    const html = `<html><body><app-root ng-version="17.3.1"></app-root>
      <script src="/main-ABCDEF.js" type="module"></script></body></html>`;
    expect(ids(html)).toEqual(["angular"]);
  });

  it("recognises Svelte on its own from a scoped class", () => {
    expect(ids(`<div class="container svelte-1x2y3z4">hi</div>`)).toEqual(["svelte"]);
  });

  it("sees a client-rendered React+Vite shell as a bundler build with no framework from HTML", () => {
    // A React client shell is a bare #root — nothing in the HTML names
    // React, so the framework is left for the source map to confirm.
    const html = `<div id="root"></div><script type="module" src="/assets/index-xyz.js"></script>
      <link rel="modulepreload" href="/assets/chunk.js">`;
    const f = detectHtml(html);
    expect(f.bundled).toBe(true);
    expect(f.vite).toBe(true);
    expect(anyFramework(f)).toBe(false);
  });

  it("finds nothing in a plain server-rendered page", () => {
    const f = detectHtml(`<html><body><h1>Hello</h1><script src="/jquery.js"></script></body></html>`);
    expect(f.bundled).toBe(false);
    expect(anyFramework(f)).toBe(false);
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
