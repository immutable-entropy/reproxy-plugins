import { describe, expect, it } from "reproxy/testing";
import { authorityOf, dirOf, originOf, resolveUrl } from "../src/url";

describe("resolveUrl", () => {
  const page = "https://app.test/dashboard/index.html";
  it("resolves the kinds of reference a build emits", () => {
    expect(resolveUrl(page, "https://cdn.test/a.js")).toBe("https://cdn.test/a.js");
    expect(resolveUrl(page, "//cdn.test/a.js")).toBe("https://cdn.test/a.js");
    expect(resolveUrl(page, "/assets/index-abc.js")).toBe("https://app.test/assets/index-abc.js");
    expect(resolveUrl(page, "app.js")).toBe("https://app.test/dashboard/app.js");
    expect(resolveUrl(page, "./app.js")).toBe("https://app.test/dashboard/app.js");
    expect(resolveUrl("https://app.test/assets/index.js", "../other/x.js.map")).toBe("https://app.test/other/x.js.map");
    expect(resolveUrl(page, "/a/../b/c.js")).toBe("https://app.test/b/c.js");
  });

  it("drops references that can't be made absolute", () => {
    expect(resolveUrl(page, "data:application/json;base64,eyJ9")).toBe("");
    expect(resolveUrl(page, "mailto:a@b.test")).toBe("");
    expect(resolveUrl(page, "")).toBe("");
    expect(resolveUrl("not a url", "/a.js")).toBe("");
  });

  it("dirOf, originOf and authorityOf", () => {
    expect(dirOf("https://app.test/assets/index-abc.js")).toBe("https://app.test/assets/");
    expect(dirOf("https://app.test/app.js?v=1")).toBe("https://app.test/");
    expect(originOf("https://app.test:8443/x/y")).toBe("https://app.test:8443");
    expect(originOf("nope")).toBe("");
    // The authority keeps the port, matching capture's Flow.host.
    expect(authorityOf("http://127.0.0.1:18090/assets/x.js")).toBe("127.0.0.1:18090");
    expect(authorityOf("https://app.test/x")).toBe("app.test");
  });
});
