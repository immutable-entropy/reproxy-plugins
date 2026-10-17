import { describe, expect, it } from "reproxy/testing";
import { readViteManifest } from "../src/manifest";

// A Vite build manifest as the docs describe it.
const manifest = {
  "_shared-B7PI925R.js": { file: "assets/shared-B7PI925R.js", name: "shared", css: ["assets/shared-ChJ_j-JJ.css"] },
  "index.html": {
    file: "assets/index-DPViepmO.js",
    name: "index",
    src: "index.html",
    isEntry: true,
    imports: ["_shared-B7PI925R.js"],
    css: ["assets/index-DItfvL25.css"],
    assets: ["assets/logo-BuF0G6sS.png"],
  },
  "src/views/about.vue": { file: "assets/about-xyz.js", src: "src/views/about.vue", isEntry: true, isDynamicEntry: false },
};

describe("readViteManifest", () => {
  it("collects every built file and names the entry points", () => {
    const vm = readViteManifest(manifest)!;
    expect(vm.files.sort()).toEqual([
      "assets/about-xyz.js",
      "assets/index-DItfvL25.css",
      "assets/index-DPViepmO.js",
      "assets/logo-BuF0G6sS.png",
      "assets/shared-B7PI925R.js",
      "assets/shared-ChJ_j-JJ.css",
    ]);
    expect(vm.entries.sort()).toEqual(["index.html", "src/views/about.vue"]);
  });

  it("rejects a progressive-web-app manifest, which is also manifest.json", () => {
    expect(readViteManifest({ name: "My App", short_name: "App", start_url: "/", icons: [{ src: "/i.png" }] })).toBeUndefined();
    expect(readViteManifest({ name: "My App", icons: [] })).toBeUndefined();
  });

  it("rejects anything whose values aren't chunk records", () => {
    expect(readViteManifest({ a: "not an object" })).toBeUndefined();
    expect(readViteManifest({ a: { name: "no file field" } })).toBeUndefined();
    expect(readViteManifest({})).toBeUndefined();
    expect(readViteManifest([1, 2])).toBeUndefined();
    expect(readViteManifest("x")).toBeUndefined();
  });
});
