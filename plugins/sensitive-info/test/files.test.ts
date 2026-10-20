// Secrets in the files the work recovered. Another plugin un-webpacks an
// exposed source map, core writes the application's own source under the
// engagement, and this plugin reads it with the same detectors it uses on
// a response body — which is the whole point of handing a recovery to
// core rather than keeping it in a variable.

import { beforeEach, describe, expect, it, mock } from "reproxy/testing";
import { load } from "../main";

beforeEach(() => load());

const config = `export const config = {
  api: "https://api.app.test",
  awsKey: "AKIAIOSFODNN7EXAMPLE",
  stripe: "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
};
`;

describe("recovered files", () => {
  it("reads a file another plugin recovered, and links the finding to it", async () => {
    const file = mock.file({
      path: "app.test/main/src/config.ts",
      content: config,
      kind: "source-map",
      url: "https://app.test/assets/index-4f1a.js.map",
      host: "app.test",
    });
    expect(await mock.dispatch("file.on_created", file)).toBe(1);

    const found = mock.findings();
    expect(found.map((f) => f.value).sort()).toEqual([
      "AKIAIOSFODNN7EXAMPLE",
      "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    ]);
    const [first] = found;
    expect(first.notes).toContain("app.test/main/src/config.ts");
    expect(first.notes).toContain("in every copy of it");
    expect(first.fields.find((f) => f.key === "where")!.value).toBe("recovered file");
    expect(first.hidden).toBe(true);
  });

  it("reads a whole recovery from its batch, each file once", async () => {
    const batch = "unpack-1";
    mock.file({ path: "app.test/main/src/a.ts", content: config, batch, batchLabel: "index.js.map" });
    const second = mock.file({
      path: "app.test/main/src/b.ts",
      content: `const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyzA";`,
      batch,
      batchLabel: "index.js.map",
    });
    // The per-file event arrives first; the batch must not read it again.
    await mock.dispatch("file.on_created", second);
    await mock.dispatch("file.on_batch_complete", mock.batch(batch)!);

    const values = mock.findings().map((f) => f.value).sort();
    expect(values).toEqual([
      "AKIAIOSFODNN7EXAMPLE",
      "ghp_1234567890abcdefghijklmnopqrstuvwxyzA",
      "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    ]);
    // Read once, so the file is linked to the finding once.
    const links = mock.findings().find((f) => f.value.indexOf("ghp_") === 0)!.links;
    expect(links.filter((l) => l.location === "recovered_file")).toHaveLength(1);
  });

  it("leaves the files alone when asked to", async () => {
    mock.settings({ scan_files: false });
    const file = mock.file({ path: "app.test/main/src/config.ts", content: config });
    await mock.dispatch("file.on_created", file);
    expect(mock.findings()).toHaveLength(0);
  });

  it("is not offered a font or an image", async () => {
    const file = mock.file({ path: "app.test/main/assets/logo.png", content: "\u0089PNG\r\n\u001a\nAKIAIOSFODNN7EXAMPLE" });
    expect(await mock.dispatch("file.on_created", file)).toBe(0);
    expect(mock.findings()).toHaveLength(0);
  });
});
