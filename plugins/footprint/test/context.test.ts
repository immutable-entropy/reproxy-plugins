import { describe, expect, it } from "reproxy/testing";
import { analyze } from "../src/context";

const html = `
<header><a href="https://twitter.com/acme">X</a></header>
<main>
  <p>A visitor wrote: see <a href="https://twitter.com/someoneelse">this thread</a>.</p>
  <a rel="me" href="https://github.com/acme">our code</a>
  <div class="social-links"><a href="https://facebook.com/acme">Facebook</a></div>
</main>
<footer><a href="https://www.linkedin.com/company/acme">LinkedIn</a></footer>
`.toLowerCase();

describe("analyze", () => {
  it("takes a link in the header, footer or nav for the site's own", () => {
    const h = analyze(html, "twitter.com/acme");
    expect(h.region).toBe("header");
    expect(h.official).toBe(true);

    const f = analyze(html, "www.linkedin.com/company/acme");
    expect(f.region).toBe("footer");
    expect(f.official).toBe(true);
  });

  it("takes a link in the page content for a possible third party's", () => {
    const b = analyze(html, "twitter.com/someoneelse");
    expect(b.region).toBe("body");
    expect(b.official).toBe(false);
  });

  it("trusts rel=\"me\" wherever it is", () => {
    const h = analyze(html, "github.com/acme");
    expect(h.region).toBe("body");
    expect(h.relMe).toBe(true);
    expect(h.official).toBe(true);
  });

  it("trusts a container that announces itself as social links", () => {
    const h = analyze(html, "facebook.com/acme");
    expect(h.region).toBe("body");
    expect(h.relMe).toBe(false);
    expect(h.official).toBe(true);
  });

  it("treats a link it can't place as body content", () => {
    expect(analyze(html, "notpresent.test/x")).toEqual({ region: "body", relMe: false, official: false });
  });
});
