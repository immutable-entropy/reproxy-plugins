import { describe, expect, it } from "reproxy/testing";
import { addToBody, buildProbe, canBody, withQuery, type Base } from "../src/probe";

const base: Base = {
  url: "https://app.test/search?q=hello",
  method: "GET",
  headers: [
    ["Host", "app.test"],
    ["Cookie", "sid=abc"],
    ["Authorization", "Bearer x"],
    ["Content-Length", "0"],
    ["Connection", "keep-alive"],
  ],
  body: "",
  contentType: "",
};
const cb = { name: "cb_run", value: "run0" };

describe("withQuery", () => {
  it("appends to an existing query", () => {
    expect(withQuery("https://a.test/p?x=1", [{ name: "y", value: "2" }])).toBe("https://a.test/p?x=1&y=2");
  });
  it("starts a query when there is none", () => {
    expect(withQuery("https://a.test/p", [{ name: "y", value: "2" }])).toBe("https://a.test/p?y=2");
  });
  it("keeps a fragment after the added params", () => {
    expect(withQuery("https://a.test/p#top", [{ name: "y", value: "2" }])).toBe("https://a.test/p?y=2#top");
  });
  it("encodes names and values", () => {
    expect(withQuery("https://a.test/p", [{ name: "a b", value: "c&d" }])).toBe("https://a.test/p?a%20b=c%26d");
  });
});

describe("buildProbe", () => {
  it("adds query candidates and the cache-buster, and drops hop-by-hop and Host", () => {
    const p = buildProbe(base, "query", [{ name: "debug", value: "zq0" }], cb);
    expect(p.url).toBe("https://app.test/search?q=hello&cb_run=run0&debug=zq0");
    const names = p.headers.map(([n]) => n.toLowerCase());
    expect(names).toContain("cookie");
    expect(names).toContain("authorization");
    expect(names).not.toContain("host");
    expect(names).not.toContain("connection");
    expect(names).not.toContain("content-length");
  });

  it("adds a header candidate, with the cache-buster still on the query", () => {
    const p = buildProbe(base, "header", [{ name: "X-Original-URL", value: "zq1" }], cb);
    expect(p.url).toBe("https://app.test/search?q=hello&cb_run=run0");
    expect(p.headers.find(([n]) => n === "X-Original-URL")?.[1]).toBe("zq1");
  });

  it("appends to the Cookie header for a cookie candidate", () => {
    const p = buildProbe(base, "cookie", [{ name: "role", value: "zq2" }], cb);
    const cookie = p.headers.find(([n]) => n.toLowerCase() === "cookie")!;
    expect(cookie[1]).toBe("sid=abc; role=zq2");
  });
});

describe("body injection", () => {
  it("adds keys to a JSON object", () => {
    const b: Base = { ...base, method: "POST", body: `{"q":"hi"}`, contentType: "application/json" };
    expect(canBody(b)).toBe(true);
    const out = JSON.parse(addToBody(b, [{ name: "debug", value: "z" }]));
    expect(out).toEqual({ q: "hi", debug: "z" });
  });

  it("appends to a form body", () => {
    const b: Base = { ...base, method: "POST", body: "q=hi", contentType: "application/x-www-form-urlencoded" };
    expect(canBody(b)).toBe(true);
    expect(addToBody(b, [{ name: "debug", value: "z" }])).toBe("q=hi&debug=z");
  });

  it("won't mine a body it can't extend", () => {
    expect(canBody({ ...base, body: "", contentType: "" })).toBe(false);
    expect(canBody({ ...base, body: "<xml/>", contentType: "application/xml" })).toBe(false);
  });
});
