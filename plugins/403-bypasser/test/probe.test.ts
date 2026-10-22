import { describe, expect, it } from "reproxy/testing";
import { buildProbe, withQuery, type Base } from "../src/probe";
import type { RawRequest, Request } from "reproxy";

const base: Base = {
  url: "https://app.test/admin?x=1",
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
const cb = { name: "cb_zz", value: "0" };

describe("withQuery", () => {
  it("appends to an existing query and starts one when absent", () => {
    expect(withQuery("https://a.test/p?x=1", [{ name: "cb", value: "0" }])).toBe("https://a.test/p?x=1&cb=0");
    expect(withQuery("https://a.test/p", [{ name: "cb", value: "0" }])).toBe("https://a.test/p?cb=0");
  });
});

describe("buildProbe (structured)", () => {
  it("sends a mutated path, adds the cache-buster, and keeps auth while dropping hop-by-hop and Host", () => {
    const p = buildProbe(base, { url: "https://app.test/admin/..;/?x=1" }, cb) as Request;
    expect(p.url).toBe("https://app.test/admin/..;/?x=1&cb_zz=0");
    const names = (p.headers as [string, string][]).map(([n]) => n.toLowerCase());
    expect(names).toContain("cookie");
    expect(names).toContain("authorization");
    expect(names).not.toContain("host");
    expect(names).not.toContain("connection");
    expect(names).not.toContain("content-length");
  });

  it("injects a header and leaves the URL (plus cache-buster) alone", () => {
    const p = buildProbe(base, { url: base.url, headers: [["X-Forwarded-For", "127.0.0.1"]] }, cb) as Request;
    expect(p.url).toBe("https://app.test/admin?x=1&cb_zz=0");
    expect((p.headers as [string, string][]).find(([n]) => n === "X-Forwarded-For")?.[1]).toBe("127.0.0.1");
  });

  it("swaps the method", () => {
    const p = buildProbe(base, { url: base.url, method: "POST" }, cb) as Request;
    expect(p.method).toBe("POST");
  });
});

describe("buildProbe (HTTP/1.0 downgrade)", () => {
  it("builds a raw request whose request line is HTTP/1.0, keeping auth by default", () => {
    const p = buildProbe(base, { url: base.url, method: "GET", downgrade: true }, cb) as RawRequest;
    expect(p.url).toBe("https://app.test/admin?x=1&cb_zz=0");
    const lines = p.raw.split("\r\n");
    expect(lines[0]).toBe("GET /admin?x=1&cb_zz=0 HTTP/1.0");
    expect(lines).toContain("Host: app.test");
    expect(lines).toContain("Cookie: sid=abc");
    expect(lines).toContain("Authorization: Bearer x");
    // Host and hop-by-hop headers are not duplicated from the original.
    expect(lines.filter((l) => l.toLowerCase().indexOf("host:") === 0)).toHaveLength(1);
    expect(p.raw.toLowerCase().indexOf("connection:")).toBe(-1);
  });

  it("strips to the request line and Host when asked", () => {
    const p = buildProbe(base, { url: base.url, method: "GET", downgrade: true, strip: true }, cb) as RawRequest;
    const lines = p.raw.split("\r\n");
    expect(lines[0]).toBe("GET /admin?x=1&cb_zz=0 HTTP/1.0");
    expect(lines).toContain("Host: app.test");
    expect(p.raw.indexOf("Cookie")).toBe(-1);
    expect(p.raw.indexOf("Authorization")).toBe(-1);
  });

  it("sets Content-Length from the body's byte length on a downgrade with a body", () => {
    const b: Base = { ...base, method: "POST", body: "é=1" }; // é is two UTF-8 bytes
    const p = buildProbe(b, { url: b.url, method: "POST", downgrade: true }, cb) as RawRequest;
    expect(p.raw).toContain("Content-Length: 4");
    expect(p.raw.endsWith("\r\n\r\né=1")).toBe(true);
  });
});
