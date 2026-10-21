// What reading a body costs. This plugin reads the HTML of every in-scope
// 200 looking for a debug page, so reading a big one that holds nothing has
// to stay well inside a turn's 250 ms — and so does reading a real error
// page, which is the largest thing a Laravel app ever sends.
//
// The shape being defended: one toLowerCase and a short list of indexOf
// calls decide whether the body is an error page at all, and the patterns
// that run afterwards are each anchored on a literal (APP_KEY,
// "laravel_version", <title>), so Go's regexp searches for that literal
// rather than walking the body. Re-run this after touching a pattern.

import { describe, expect, it } from "reproxy/testing";
import { readHtmlError } from "../src/debug";
import { fromHtml } from "../src/detect";

const row = `<tr><td>Widget number 12345</td><td>WX-1234-AB</td><td>19.99</td><td>2026-01-01</td></tr>`;
function page(kb: number, unit = row): string {
  return "<html><body><table>" + unit.repeat(Math.ceil((kb * 1024) / unit.length)) + "</table></body></html>";
}

function tick(): Promise<void> {
  return new Promise((done) => setTimeout(done, 0));
}
function ms(fn: () => void): number {
  const start = Date.now();
  fn();
  return Date.now() - start;
}

/** What onBody does to a body: lower-case it, then read it. */
function read(body: string): void {
  const lower = body.toLowerCase();
  fromHtml(lower);
  readHtmlError(body, lower);
}

describe("cost", () => {
  it("reads a 512 KiB page with nothing in it inside the budget", async () => {
    await tick();
    const big = page(512);
    const took = ms(() => read(big));
    console.log(`512 KiB of ordinary HTML: ${took} ms`);
    expect(took).toBeLessThan(150);
  });

  it("reads a 512 KiB error page inside the budget", async () => {
    await tick();
    // A real Ignition page: the whole body is a stack trace, so every
    // pattern runs and the needles all hit.
    const frame = `<div class="frame"><span>/srv/shop/vendor/laravel/framework/src/Illuminate/Database/Connection.php</span><span>760</span></div>`;
    const big =
      `<html><head><title>SQLSTATE[42S02]: Base table not found</title></head><body>` +
      `<script>window.data={"context":{"env":{"laravel_version":"10.48.4","php_version":"8.2.12","app_env":"production"}}}</script>` +
      frame.repeat(Math.ceil((512 * 1024) / frame.length)) +
      `</body></html>`;
    const took = ms(() => {
      const e = readHtmlError(big, big.toLowerCase())!;
      expect(e.laravelVersion).toBe("10.48.4");
      expect(e.root).toBe("/srv/shop");
    });
    console.log(`512 KiB error page: ${took} ms`);
    expect(took).toBeLessThan(200);
  });

  it("survives a page that looks like an environment table but isn't", async () => {
    await tick();
    // The worst case for the APP_KEY pattern: its anchor everywhere and
    // never a key to find, so the pattern restarts at every hit.
    const noisy =
      `<h1>Whoops, looks like something went wrong.</h1>` +
      page(512, `<tr><td>APP_KEY</td><td>set via the environment, not shown here</td></tr>`);
    const took = ms(() => {
      const e = readHtmlError(noisy, noisy.toLowerCase())!;
      expect(e.appKey).toBe("");
    });
    console.log(`512 KiB of APP_KEY anchors with no key: ${took} ms`);
    expect(took).toBeLessThan(200);
  });
});
