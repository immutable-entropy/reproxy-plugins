import { describe, it, expect } from "reproxy/testing";
import { extract, looksLikeURL, openapi, resolve, robots, scriptCalls, sitemap } from "../src/extract";

const opts = { max: 500, openapi: true };
const urls = (body: string, base: string, ct: string) => extract(body, base, ct, opts).map((f) => `${f.url} ${f.detail}`);

describe("resolve", () => {
  it("makes URLs absolute", () => {
    expect(resolve("/a/b?x=1", "https://app.test/c/d")).toBe("https://app.test/a/b?x=1");
    expect(resolve("e", "https://app.test/c/d")).toBe("https://app.test/c/e");
    expect(resolve("../e", "https://app.test/c/d/f")).toBe("https://app.test/c/e");
    expect(resolve("//cdn.test/x.js", "https://app.test/")).toBe("https://cdn.test/x.js");
    expect(resolve("HTTP://API.App.Test/v1", "https://app.test/")).toBe("http://api.app.test/v1");
    expect(resolve("mailto:a@b.test", "https://app.test/")).toBeNull();
  });

  it("knows a URL-ish string from text", () => {
    expect(looksLikeURL("/api/v1/users")).toBe(true);
    expect(looksLikeURL("https://api.app.test/x")).toBe(true);
    expect(looksLikeURL("/")).toBe(false);
    expect(looksLikeURL("/2024/01")).toBe(false);
    expect(looksLikeURL("hello world")).toBe(false);
  });
});

describe("JSON", () => {
  it("finds URLs in values, with their path", () => {
    const body = JSON.stringify({ links: [{ href: "/api/orders" }], next: "https://api.app.test/v2/page/2", name: "x" });
    const got = urls(body, "https://app.test/api", "application/json");
    expect(got).toContain("https://app.test/api/orders json:$.links[0].href");
    expect(got).toContain("https://api.app.test/v2/page/2 json:$.next");
  });

  it("reads OpenAPI documents", () => {
    const doc = {
      openapi: "3.0.0",
      servers: [{ url: "https://api.app.test/v1" }],
      paths: { "/users/{userId}": { get: {}, delete: {} }, "/health": { get: {} } },
    };
    expect(openapi(doc, "https://app.test/openapi.json")).toEqual([
      { url: "https://api.app.test/v1/users/{userId}", detail: "openapi:GET,DELETE /users/{userId}" },
      { url: "https://api.app.test/v1/health", detail: "openapi:GET /health" },
    ]);
  });

  it("reads Swagger 2 documents", () => {
    const doc = { swagger: "2.0", host: "api.app.test", basePath: "/v2", schemes: ["https"], paths: { "/pets": { post: {} } } };
    expect(openapi(doc, "https://app.test/")[0].url).toBe("https://api.app.test/v2/pets");
  });
});

describe("scripts", () => {
  it("finds API calls", () => {
    const js = `fetch("/api/me"); axios.post('/api/orders', o); x.open("GET", "https://api.app.test/v1/q"); $.ajax({url: "/legacy/thing"})`;
    expect(scriptCalls(js)).toEqual([
      { url: "/api/me", via: "fetch" },
      { url: "/api/orders", via: "axios" },
      { url: "https://api.app.test/v1/q", via: "xhr" },
      { url: "/legacy/thing", via: "url" },
    ]);
  });
});

describe("robots and sitemaps", () => {
  it("reads robots.txt", () => {
    const got = robots("User-agent: *\nDisallow: /admin/\nAllow: /public/*.html\nSitemap: https://app.test/sitemap.xml\nDisallow: /");
    expect(got.map((f) => f.url)).toEqual(["/admin/", "/public/", "https://app.test/sitemap.xml"]);
  });

  it("reads sitemaps", () => {
    expect(sitemap("<urlset><url><loc>https://app.test/a?x=1&amp;y=2</loc></url><url><loc> https://app.test/b </loc></url></urlset>")).toEqual([
      "https://app.test/a?x=1&y=2",
      "https://app.test/b",
    ]);
  });

  it("only reads robots.txt as robots", () => {
    expect(urls("Disallow: /secret", "https://app.test/notes.txt", "text/plain")).toEqual([]);
    expect(urls("Disallow: /secret", "https://app.test/robots.txt", "text/plain")).toEqual(["https://app.test/secret robots:disallow"]);
  });
});

describe("HTML", () => {
  it("falls back to Go's sweep of attributes", () => {
    const got = urls(`<a href="/about">a</a><script src="https://cdn.test/app.js"></script>`, "https://app.test/", "text/html");
    expect(got).toEqual(["https://app.test/about html", "https://cdn.test/app.js html"]);
  });

  it("respects the limit", () => {
    const body = Array.from({ length: 20 }, (_, i) => `<a href="/p${i}">x</a>`).join("");
    expect(extract(body, "https://app.test/", "text/html", { max: 5, openapi: true })).toHaveLength(5);
  });
});
