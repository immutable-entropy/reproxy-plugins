import { describe, expect, it, mock } from "reproxy/testing";
import type { Finding } from "reproxy";

const page = `<!doctype html><html><head>
<script>gtag('config','G-ABCDE12345');</script>
</head><body>
<main><article>
  A visitor linked <a href="https://twitter.com/randomperson">their account</a>
  and <a href="https://twitter.com/acme/status/999">a post of ours</a>.
</article></main>
<footer class="site-footer">
  <a href="https://twitter.com/acme">Twitter</a>
  <a href="https://github.com/acme/widget">Source</a>
  <a href="mailto:hello@acme.test">Email us</a>
  <img src="https://acme-assets.s3.amazonaws.com/logo.png">
</footer>
</body></html>`;

const respond = (body = page) =>
  mock.dispatch("traffic.on_response_received", {
    url: "https://acme.test/",
    responseHeaders: { "Content-Type": "text/html" },
    responseBody: body,
  });

function field(f: Finding, key: string): string | undefined {
  return f.fields.find((x) => x.key === key)?.value;
}
function byValue(v: string): Finding | undefined {
  return mock.findings().find((f) => f.value === v);
}

describe("scanResponse", () => {
  it("records the organisation's own accounts, repositories, contacts and services", async () => {
    await respond();
    const found = mock.findings();

    const twitter = byValue("https://twitter.com/acme");
    expect(twitter?.types).toEqual(["social-account"]);
    expect(field(twitter!, "source")).toBe("the site itself");
    expect(twitter!.hidden).toBe(false);

    expect(byValue("https://github.com/acme/widget")?.types).toEqual(["source-repo"]);
    expect(byValue("hello@acme.test")?.types).toEqual(["contact"]);
    expect(byValue("G-ABCDE12345")?.types).toEqual(["service-id"]);
    expect(byValue("acme-assets")?.types).toEqual(["cloud-storage"]);

    // The five above, and the visitor's account below.
    expect(found.length).toBeGreaterThan(5);
  });

  it("marks a link in the page content as a possible third party's", async () => {
    await respond();
    const other = byValue("https://twitter.com/randomperson");
    expect(other).toBeDefined();
    expect(field(other!, "source")).toBe("page content");
    expect(other!.notes).toContain("may belong to a third party");
  });

  it("leaves out links to individual posts by default", async () => {
    await respond();
    expect(mock.findings().some((f) => f.value.indexOf("/status/999") >= 0)).toBe(false);
  });

  it("includes content links when asked", async () => {
    mock.settings({ include_content_links: true });
    await respond();
    expect(mock.findings().some((f) => f.value.indexOf("/status/999") >= 0)).toBe(true);
  });

  it("can skip a whole category", async () => {
    mock.settings({ skip_detectors: ["social-account"] });
    await respond();
    expect(mock.findings().some((f) => f.types[0] === "social-account")).toBe(false);
    expect(mock.findings().some((f) => f.types[0] === "source-repo")).toBe(true);
  });

  it("merges an account linked more than once into one finding", async () => {
    await respond();
    await respond();
    const twitter = mock.findings().filter((f) => f.value === "https://twitter.com/acme");
    expect(twitter).toHaveLength(1);
    expect(twitter[0].links.length).toBe(2);
  });

  it("is not called for a non-text response", async () => {
    const n = await mock.dispatch("traffic.on_response_received", {
      url: "https://acme.test/logo.png",
      responseHeaders: { "Content-Type": "image/png" },
      responseBody: "mailto:hello@acme.test https://twitter.com/acme",
    });
    expect(n).toBe(0);
    expect(mock.findings()).toHaveLength(0);
  });
});
