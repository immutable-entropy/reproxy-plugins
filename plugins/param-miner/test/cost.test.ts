// What judging a probe costs. The action waits on the network between
// probes, so the only CPU that runs in one turn is building a request and
// reading one response. The read is a reflection scan: a single indexOf for
// the run prefix, and then, only if it is present, one per name in the
// batch. This proves that stays cheap on a large body, so a turn never
// approaches its 250 ms budget.

import { describe, expect, it } from "reproxy/testing";
import { canaryValue, reflected, type Candidate } from "../src/detect";

function tick(): Promise<void> {
  return new Promise((done) => setTimeout(done, 0));
}
function ms(fn: () => void): number {
  const start = Date.now();
  fn();
  return Date.now() - start;
}

function batch(prefix: string, n: number): Candidate[] {
  return Array.from({ length: n }, (_, i) => ({ name: `p${i}`, location: "query" as const, value: canaryValue(prefix, i) }));
}

describe("cost", () => {
  it("scans a 1 MiB body that reflects nothing in well under a turn", async () => {
    await tick();
    const body = "x".repeat(1024 * 1024);
    const cands = batch("zq7f", 24);
    const took = ms(() => {
      for (let i = 0; i < 20; i++) reflected(body, "zq7f", cands);
    });
    console.log(`20 scans of 1 MiB, nothing reflected: ${took} ms`);
    expect(took).toBeLessThan(100);
  });

  it("scans a 1 MiB body that does reflect one name inside the budget", async () => {
    await tick();
    const cands = batch("zq7f", 24);
    const body = "x".repeat(1024 * 1024) + cands[23].value;
    const took = ms(() => {
      for (let i = 0; i < 20; i++) expect(reflected(body, "zq7f", cands)).toHaveLength(1);
    });
    console.log(`20 scans of 1 MiB, one reflected: ${took} ms`);
    expect(took).toBeLessThan(200);
  });
});
