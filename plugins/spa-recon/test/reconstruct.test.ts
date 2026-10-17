import { describe, expect, it } from "reproxy/testing";
import { readSourceMap } from "../src/sourcemap";
import { recoverFiles } from "../src/reconstruct";

const map = readSourceMap({
  version: 3,
  mappings: "AAAA",
  sources: [
    "../../src/main.ts",
    "../../src/api/client.ts",
    "../../src/main.ts", // a duplicate path (two chunks, same module)
    "../../node_modules/.pnpm/vue@3.4.21/node_modules/vue/dist/vue.mjs",
    "\u0000virtual:/vite/preload-helper",
  ],
  sourcesContent: [
    "import { createApp } from 'vue'",
    "export const api = 'https://api.app.test/v1'",
    "import { createApp } from 'vue'",
    "export const version = '3.4.21'",
    null, // no content for the virtual module
  ],
})!;

describe("recoverFiles", () => {
  it("reconstructs the files with content, app code first, and dedupes paths", () => {
    const files = recoverFiles(map);
    // The virtual module has no content, so it is left out; the duplicate
    // path appears once. App files come before the dependency.
    expect(files.map((f) => `${f.app ? "app" : "dep"} ${f.path}`)).toEqual([
      "app src/main.ts",
      "app src/api/client.ts",
      "dep node_modules/.pnpm/vue@3.4.21/node_modules/vue/dist/vue.mjs",
    ]);
    expect(files[1].content).toContain("https://api.app.test/v1");
  });

  it("honours the overall limit", () => {
    expect(recoverFiles(map, 1).length).toBe(1);
  });

  it("recovers nothing from a map that carries no content", () => {
    const paths = readSourceMap({ version: 3, mappings: "A", sources: ["src/a.ts", "src/b.ts"] })!;
    expect(recoverFiles(paths)).toEqual([]);
  });
});
