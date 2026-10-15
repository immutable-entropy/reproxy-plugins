import { describe, expect, it } from "reproxy/testing";
import { pluginProbes, probePath, readmeVersion, styleVersion, themeProbes } from "../src/active";

describe("readmeVersion", () => {
  it("reads the Stable tag line", () => {
    const readme = `=== Contact Form 7 ===\nContributors: takayukister\nStable tag: 5.9.2\nRequires at least: 6.0\n\n== Description ==`;
    expect(readmeVersion(readme)).toBe("5.9.2");
  });

  it("is case- and whitespace-insensitive", () => {
    expect(readmeVersion("STABLE TAG:   2.3.1\n")).toBe("2.3.1");
  });

  it("falls back to a Version header", () => {
    expect(readmeVersion("Plugin Name: X\nVersion: 1.4.0\n")).toBe("1.4.0");
  });

  it("rejects a 'Stable tag: trunk' or other non-version", () => {
    expect(readmeVersion("Stable tag: trunk\n")).toBe("");
    expect(readmeVersion("nothing here")).toBe("");
  });
});

describe("styleVersion", () => {
  it("reads the Version header from a style.css block", () => {
    const css = `/*\nTheme Name: Twenty Twenty-Four\nAuthor: WordPress team\nVersion: 1.2\nText Domain: twentytwentyfour\n*/\nbody{}`;
    expect(styleVersion(css)).toBe("1.2");
  });

  it("finds nothing in plain CSS", () => {
    expect(styleVersion("body{color:red}")).toBe("");
  });
});

describe("probe URLs", () => {
  it("builds the plugin readme path", () => {
    expect(pluginProbes("https", "blog.test", "akismet")).toEqual([
      { url: "https://blog.test/wp-content/plugins/akismet/readme.txt", read: readmeVersion },
    ]);
  });

  it("builds the theme style.css then readme", () => {
    const got = themeProbes("http", "blog.test:8080", "storefront").map((p) => p.url);
    expect(got).toEqual([
      "http://blog.test:8080/wp-content/themes/storefront/style.css",
      "http://blog.test:8080/wp-content/themes/storefront/readme.txt",
    ]);
  });

  it("extracts the path for a finding note", () => {
    expect(probePath("https://blog.test/wp-content/plugins/akismet/readme.txt")).toBe(
      "/wp-content/plugins/akismet/readme.txt",
    );
  });
});
