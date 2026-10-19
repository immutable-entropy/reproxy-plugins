// What a scan costs. Like the sensitive-info plugin, footprint reads a body
// on every in-scope response, so the cost of reading a big one that holds
// nothing has to stay well inside a turn's 250 ms. The link extraction runs
// in Go (text.urls); what is measured here is the part this plugin drives:
// the anchored service patterns and the bounded email/phone scan.

import { describe, expect, it } from "reproxy/testing";
import { scan, type Options } from "../src/patterns";

const opts: Options = { maxPii: 128 * 1024, ignoreEmails: [], max: 50 };

const row = `{"id":12345,"name":"Widget number 12345","sku":"WX-1234-AB","price":19.99,"updated":"2026-01-01T00:00:00Z"},`;
function body(kb: number, unit = row): string {
  return "[" + unit.repeat(Math.ceil((kb * 1024) / unit.length)) + "]";
}

function tick(): Promise<void> {
  return new Promise((done) => setTimeout(done, 0));
}
function ms(fn: () => void): number {
  const start = Date.now();
  fn();
  return Date.now() - start;
}

describe("cost", () => {
  it("reads a 512 KiB body with nothing in it inside the budget", async () => {
    await tick();
    const big = body(512);
    const took = ms(() => scan(big, opts));
    console.log(`512 KiB with nothing in it: ${took} ms`);
    expect(took).toBeLessThan(150);
  });

  it("reads a body full of anchor-like noise inside the budget", async () => {
    await tick();
    // "g-", "ua-" and "@" everywhere: the worst case for the gate, since it
    // turns the analytics and email patterns on over the whole slice.
    const noisy = body(512, `{"a":"g-1","b":"ua-2","c":"x@y","tel":"tel:+1"},`);
    const took = ms(() => scan(noisy, opts));
    console.log(`512 KiB of anchor-like noise: ${took} ms`);
    expect(took).toBeLessThan(200);
  });

  it("still finds what is there", async () => {
    await tick();
    const big = body(256);
    const planted = big.slice(0, 50000) + `,{"dsn":"https://abcdef0123456789abcdef0123456789@o1.ingest.sentry.io/9","m":"mailto:ops@acme.test"},` + big.slice(50000);
    const got = scan(planted, opts).map((h) => h.detector);
    expect(got).toContain("sentry_dsn");
    expect(got).toContain("email_mailto");
  });
});
