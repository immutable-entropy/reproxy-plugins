// What a scan costs. Every plugin turn has 250 ms of CPU, and this plugin
// reads every message of every targeted flow, so the cost of a scan is as
// much a part of it working as what it finds. These are the measurements
// that justify the design in src/detectors.ts: re-run them after touching
// a pattern.
//
// The bounds are generous — a shared machine under load is slower than a
// quiet one — but a change that breaks the design (an unanchored pattern
// over the whole body, a capturing group in a composed pattern) costs
// multiples, not percentages, and these catch it.

import { describe, it, expect } from "reproxy/testing";
import { scan, type Options } from "../src/detectors";

const opts: Options = {
  detectors: [],
  skip: [],
  minEntropy: 3.5,
  maxBody: 512 * 1024,
  maxPii: 128 * 1024,
  ignoreValues: [],
  hexHashes: false,
  maxHits: 25,
};

// A body like a real API's: nothing sensitive in it, which is the case that
// has to be cheap, because it is nearly every message.
const row = `{"id":12345,"name":"Widget number 12345","sku":"WX-1234-AB","price":19.99,"tags":["a","b"],"updated":"2026-01-01T00:00:00Z"},`;
const head = [
  "GET /api/items?page=2 HTTP/1.1",
  "Host: app.test",
  "User-Agent: Mozilla/5.0",
  "Authorization: Bearer abc123def456ghi",
  "Cookie: theme=dark; PHPSESSID=8f2kq9d1x7bqw3zt5r6y",
  "",
  "",
].join("\r\n");

function body(kb: number): string {
  return "[" + row.repeat(Math.ceil((kb * 1024) / row.length)) + "]";
}

// A turn of one's own: each hook call a plugin gets has its own 250 ms, and
// a promise that is already resolved continues in the same turn, so a
// measurement that wants a fresh one has to wait for a timer.
function tick(): Promise<void> {
  return new Promise((done) => setTimeout(done, 0));
}

function ms(fn: () => void): number {
  const start = Date.now();
  fn();
  return Date.now() - start;
}

describe("cost", () => {
  it("reads a 512 KiB body inside one turn's budget", async () => {
    await tick(); // the measurement gets a turn of its own
    const big = body(512);
    const took = ms(() => scan({ side: "response", head, body: big }, opts));
    console.log(`512 KiB with nothing in it: ${took} ms`);
    expect(took).toBeLessThan(200);
  });

  it("reads a body full of candidate words inside the budget", async () => {
    await tick();
    // Every field name this plugin looks at, over and over: the worst case
    // for the window budget.
    const noisy = `{"user":"u","key":"k","token":"t","session":"s","account":"a","mail":"m","card":"c"},`;
    const big = "[" + noisy.repeat(Math.ceil((512 * 1024) / noisy.length)) + "]";
    const took = ms(() => scan({ side: "response", head, body: big }, opts));
    console.log(`512 KiB of candidate names: ${took} ms`);
    expect(took).toBeLessThan(200);
  });

  it("reads a small body in no time at all", async () => {
    await tick();
    const login = "username=ann&password=hunter2&remember=1";
    const took = ms(() => {
      for (let i = 0; i < 20; i++) scan({ side: "request", head, query: "next=/account", body: login }, opts);
    });
    console.log(`a login, 20 times: ${took} ms`);
    expect(took).toBeLessThan(100);
  });

  it("still finds what is there", async () => {
    await tick();
    const big = body(256);
    const planted = big.slice(0, 100000) + `,{"aws":"AKIAIOSFODNN7EXAMPLE","password":"hunter2"},` + big.slice(100000);
    const got = scan({ side: "response", head, body: planted }, opts).map((h) => h.detector);
    expect(got).toContain("aws_access_key");
    expect(got).toContain("field_password");
  });
});
