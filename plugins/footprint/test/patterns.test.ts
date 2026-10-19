import { describe, expect, it } from "reproxy/testing";
import { keepEmail, scan, type Options } from "../src/patterns";

const base: Options = { maxPii: 1 << 20, ignoreEmails: [], max: 500 };

/** "detector=value" for everything scan finds in a body. */
function f(body: string, o: Partial<Options> = {}): string[] {
  return scan(body, { ...base, ...o }).map((h) => `${h.detector}=${h.value}`);
}

describe("links that aren't URLs", () => {
  it("reads mailto: and tel: links", () => {
    expect(f(`<a href="mailto:info@acme.test">mail</a>`)).toContain("email_mailto=info@acme.test");
    expect(f(`<a href="tel:+1 415 555 0199">call</a>`)).toContain("phone_tel=+1 415 555 0199");
  });

  it("reads an s3:// bucket URI", () => {
    expect(f("backup at s3://acme-prod-backups/db.sql")).toContain("s3_uri=acme-prod-backups");
  });
});

describe("third-party service identifiers", () => {
  it("reads analytics and tag-manager ids", () => {
    expect(f("gtag('config', 'G-ABCDE12345');")).toContain("ga4=G-ABCDE12345");
    expect(f("_gaq.push(['_setAccount', 'UA-123456-1']);")).toContain("ua=UA-123456-1");
    expect(f(`<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABCD12">`)).toContain("gtm=GTM-ABCD12");
  });

  it("reads a Sentry DSN and a Stripe publishable key", () => {
    expect(f(`Sentry.init({dsn:"https://abcdef0123456789abcdef0123456789@o42.ingest.us.sentry.io/4504"})`)).toContain(
      "sentry_dsn=https://abcdef0123456789abcdef0123456789@o42.ingest.us.sentry.io/4504",
    );
    expect(f(`Stripe('pk_live_51Habcdefghijklmnop')`)).toContain("stripe_pk=pk_live_51Habcdefghijklmnop");
  });

  it("reads a Facebook Pixel, a Segment key and an Intercom app id", () => {
    expect(f(`fbq('init', '1234567890123456');`)).toContain("fb_pixel=1234567890123456");
    expect(f(`analytics.load("aB12cd34EF56gh");`)).toContain("segment_key=aB12cd34EF56gh");
    expect(f(`window.intercomSettings = { app_id: "ab12cd34" };`)).toContain("intercom_app=ab12cd34");
  });
});

describe("contact details", () => {
  it("reads a postal address from structured data", () => {
    expect(f(`{"@type":"PostalAddress","streetAddress":"123 Example Street","postalCode":"90210"}`)).toContain(
      "postal_address=123 Example Street",
    );
  });

  it("reads emails from the text, skipping ignored domains and asset names", () => {
    const got = f("contact dev@acme.test or sales@example.com; logo is logo@2x.png", { ignoreEmails: ["example.com"] });
    expect(got).toContain("email=dev@acme.test");
    expect(got).not.toContain("email=sales@example.com");
    expect(got.some((g) => g.indexOf("logo@2x.png") >= 0)).toBe(false);
  });

  it("reads a plausible telephone number from the text", () => {
    expect(f("call us on +14155550199 any time")).toContain("phone=+14155550199");
    expect(f("the answer is +42")).not.toContain("phone=+42");
  });

  it("records an email seen twice (mailto and text) only once", () => {
    const got = scan(`<a href="mailto:info@acme.test">info@acme.test</a>`, base).filter((h) => h.value === "info@acme.test");
    expect(got).toHaveLength(1);
  });
});

describe("keepEmail", () => {
  it("drops asset names and ignored domains", () => {
    expect(keepEmail("ann@acme.test", [])).toBe(true);
    expect(keepEmail("logo@2x.png", [])).toBe(false);
    expect(keepEmail("ann@mail.example.com", ["example.com"])).toBe(false);
  });
});
