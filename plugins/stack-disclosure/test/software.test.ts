import { describe, expect, it } from "reproxy/testing";
import { cpeVersion, isFullVersion, parseBanners, softwareInHead } from "../src/software";

const head = (...lines: string[]) => ["HTTP/1.1 200 OK", ...lines].join("\r\n") + "\r\n\r\n";

describe("parseBanners", () => {
  it("reads one NAME/VERSION pair", () => {
    expect(parseBanners("nginx/1.18.0")).toEqual([{ product: "nginx", version: "1.18.0" }]);
  });
  it("reads every pair a chained banner names", () => {
    expect(parseBanners("Apache/2.4.41 (Unix) OpenSSL/1.1.1d PHP/7.4.3")).toEqual([
      { product: "apache", version: "2.4.41" },
      { product: "openssl", version: "1.1.1d" },
      { product: "php", version: "7.4.3" },
    ]);
  });
  it("reads a NAME VERSION banner (BigIP 16.1.0)", () => {
    expect(parseBanners("BigIP 16.1.0")).toEqual([{ product: "bigip", version: "16.1.0" }]);
  });
  it("doesn't also read the spaced form once a slash form matched", () => {
    expect(parseBanners("Apache/2.4.41 (Debian)")).toEqual([{ product: "apache", version: "2.4.41" }]);
  });
  it("names nothing for a bare product or a non-version number", () => {
    expect(parseBanners("nginx")).toEqual([]);
    expect(parseBanners("cloudflare")).toEqual([]);
  });
});

describe("softwareInHead", () => {
  it("collects from the version-carrying headers only", () => {
    const h = head(
      "Server: nginx/1.18.0",
      "X-Powered-By: PHP/7.4.3",
      "Date: Mon, 01 Jan 2024 00:00:00 GMT",
      "Content-Length: 12",
    );
    expect(softwareInHead(h)).toEqual([
      { product: "nginx", version: "1.18.0" },
      { product: "php", version: "7.4.3" },
    ]);
  });
  it("de-duplicates a product named twice", () => {
    const h = head("Server: nginx/1.18.0", "Via: nginx/1.18.0");
    expect(softwareInHead(h)).toHaveLength(1);
  });
});

describe("isFullVersion", () => {
  it("wants all of major.minor.patch", () => {
    expect(isFullVersion("16.1.0")).toBe(true);
    expect(isFullVersion("2.4.41")).toBe(true);
    expect(isFullVersion("1.1.1d")).toBe(true);
    expect(isFullVersion("1.18")).toBe(false);
    expect(isFullVersion("16")).toBe(false);
  });
});

describe("cpeVersion", () => {
  it("drops a distribution or build suffix, keeps an OpenSSL letter", () => {
    expect(cpeVersion("7.4.3-1ubuntu2")).toBe("7.4.3");
    expect(cpeVersion("1.1.1d")).toBe("1.1.1d");
    expect(cpeVersion("2.4.41")).toBe("2.4.41");
    expect(cpeVersion("16.1.0+build.5")).toBe("16.1.0");
  });
});
