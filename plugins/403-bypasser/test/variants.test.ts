import { describe, expect, it } from "reproxy/testing";
import {
  build,
  downgradeVariant,
  headerVariants,
  hostOf,
  methodVariants,
  overrideBaseUrl,
  overrideVariants,
  parts,
  pathOf,
  pathVariants,
  requestTarget,
} from "../src/variants";

describe("URL helpers", () => {
  it("splits a URL into origin, path and query, dropping the fragment", () => {
    const p = parts("https://app.test:8443/a/b?x=1#top");
    expect(p.origin).toBe("https://app.test:8443");
    expect(p.path).toBe("/a/b");
    expect(p.query).toBe("x=1");
  });
  it("defaults an empty path to /", () => {
    expect(parts("https://app.test").path).toBe("/");
  });
  it("rebuilds, and reads path/target/host", () => {
    expect(build("https://app.test", "/a", "x=1")).toBe("https://app.test/a?x=1");
    expect(pathOf("https://app.test/a/b?x=1")).toBe("/a/b");
    expect(requestTarget("https://app.test/a/b?x=1")).toBe("/a/b?x=1");
    expect(hostOf("https://app.test:8443/a?x=1")).toBe("app.test:8443");
  });
});

describe("pathVariants", () => {
  const V = pathVariants("https://app.test/admin", []);
  const urls = V.map((v) => v.mutation.url);

  it("never leaves the path unchanged", () => {
    expect(urls.indexOf("https://app.test/admin")).toBe(-1);
  });
  it("adds the structural tricks", () => {
    expect(urls).toContain("https://app.test/admin/");
    expect(urls).toContain("https://app.test/admin/..;/");
    expect(urls).toContain("https://app.test/ADMIN");
    expect(urls).toContain("https://app.test/admin.json");
    expect(urls).toContain("https://app.test//admin"); // doubled slashes
  });
  it("applies the bundled-style payloads given to it", () => {
    const withPayloads = pathVariants("https://app.test/admin", ["..;", "%2f"]).map((v) => v.mutation.url);
    expect(withPayloads).toContain("https://app.test/admin/..;/");
    expect(withPayloads).toContain("https://app.test/admin%2f");
  });
  it("keeps the query on every variant", () => {
    const q = pathVariants("https://app.test/admin?x=1", []).map((v) => v.mutation.url);
    expect(q.every((u) => u.indexOf("?x=1") >= 0)).toBe(true);
  });
  it("de-duplicates by resulting URL", () => {
    expect(new Set(urls).size).toBe(urls.length);
  });
});

describe("headerVariants", () => {
  it("parses Name: Value lines and defaults a bare name to 127.0.0.1", () => {
    const V = headerVariants("https://app.test/a", ["X-Forwarded-For: 127.0.0.1", "X-True-IP"]);
    const ff = V.find((v) => v.detail.indexOf("X-Forwarded-For") >= 0)!;
    expect(ff.mutation.headers).toEqual([["X-Forwarded-For", "127.0.0.1"]]);
    const tip = V.find((v) => v.detail.indexOf("X-True-IP") >= 0)!;
    expect(tip.mutation.headers).toEqual([["X-True-IP", "127.0.0.1"]]);
    expect(V.every((v) => v.mutation.url === "https://app.test/a")).toBe(true);
  });
});

describe("overrideVariants", () => {
  it("requests the base path with the blocked path (and query) in the header", () => {
    const V = overrideVariants("https://app.test/admin?x=1", "/", ["X-Original-URL"]);
    expect(V).toHaveLength(1);
    expect(V[0].mutation.url).toBe("https://app.test/");
    expect(V[0].mutation.headers).toEqual([["X-Original-URL", "/admin?x=1"]]);
  });
  it("names the base URL the control request uses", () => {
    expect(overrideBaseUrl("https://app.test/admin", "/")).toBe("https://app.test/");
    expect(overrideBaseUrl("https://app.test/admin", "status")).toBe("https://app.test/status");
  });
});

describe("methodVariants", () => {
  it("skips the request's own method and upper-cases the rest", () => {
    const V = methodVariants("https://app.test/a", "GET", ["GET", "post", "HEAD"]);
    const methods = V.map((v) => v.mutation.method);
    expect(methods.indexOf("GET")).toBe(-1);
    expect(methods).toContain("POST");
    expect(methods).toContain("HEAD");
  });
});

describe("downgradeVariant", () => {
  it("marks the mutation as a downgrade and carries the strip flag", () => {
    const v = downgradeVariant("https://app.test/a", "GET", true);
    expect(v.technique).toBe("downgrade");
    expect(v.mutation.downgrade).toBe(true);
    expect(v.mutation.strip).toBe(true);
    expect(v.mutation.method).toBe("GET");
  });
});
