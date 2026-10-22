// What the plugin's own work costs, apart from the network. Generating the
// variants runs in goja on the picked request, and judging a response compares
// bodies that can be large, so both have to stay well inside a turn's 250 ms.
// The sending itself is paced and awaited, so it doesn't count here.

import { describe, expect, it } from "reproxy/testing";
import { pathVariants } from "../src/variants";
import { blockedBaselineOf, reacted, signalOf } from "../src/detect";

function tick(): Promise<void> {
  return new Promise((done) => setTimeout(done, 0));
}
function ms(fn: () => void): number {
  const start = Date.now();
  fn();
  return Date.now() - start;
}

const PATH_PAYLOADS = ["%09", "%20", "%23", "%2e", "%2f", ".", ";", "..;", ";%09", ";%09..", ";%09..;", ";%2f..", "*"];

describe("cost", () => {
  it("generates variants for a deep path quickly and stays bounded", async () => {
    await tick();
    // A pathologically deep path: a slash to insert around at every segment.
    const deep = "/" + Array.from({ length: 60 }, (_, i) => `seg${i}`).join("/");
    let count = 0;
    const took = ms(() => {
      count = pathVariants("https://app.test" + deep, PATH_PAYLOADS).length;
    });
    console.log(`path variants for a 60-segment path: ${count} in ${took} ms`);
    expect(count).toBeLessThan(501); // the MAX_PATH cap
    expect(took).toBeLessThan(150);
  });

  it("judges large responses against the baseline cheaply", async () => {
    await tick();
    const block = "<html>denied</html>" + "x".repeat(512 * 1024);
    const bl = blockedBaselineOf([signalOf(403, block.length, block), signalOf(403, block.length, block)]);
    // A 200 the same size as the block page but differing only at the very end:
    // the worst case for the body comparison.
    const body = "<html>denied</html>" + "x".repeat(512 * 1024 - 1) + "Y";
    const s = signalOf(200, body.length, body);
    const took = ms(() => {
      for (let i = 0; i < 50; i++) reacted(bl, s, { blocked: [401, 403], includeRedirects: false });
    });
    console.log(`50 judgements of a 512 KiB body: ${took} ms`);
    expect(took).toBeLessThan(150);
  });
});
