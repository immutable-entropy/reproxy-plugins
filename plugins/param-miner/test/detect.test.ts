import { describe, expect, it } from "reproxy/testing";
import {
  baselineOf,
  canaryValue,
  howChanged,
  lengthChanged,
  reflected,
  signalOf,
  statusChanged,
  type Candidate,
} from "../src/detect";

const sig = (status: number, length: number) => signalOf(status, length);

describe("baselineOf", () => {
  it("keeps a status the samples agree on, drops one they don't", () => {
    expect(baselineOf([sig(200, 100), sig(200, 102)]).status).toBe(200);
    expect(baselineOf([sig(200, 100), sig(500, 100)]).status).toBe(-1);
  });

  it("calls a page with small jitter stable and a wildly varying one not", () => {
    expect(baselineOf([sig(200, 1000), sig(200, 1010)]).lengthStable).toBe(true);
    expect(baselineOf([sig(200, 1000), sig(200, 2000)]).lengthStable).toBe(false);
  });
});

describe("change detection", () => {
  const base = baselineOf([sig(200, 1000), sig(200, 1008)]);

  it("sees a status change only against a stable status", () => {
    expect(statusChanged(base, sig(500, 1000))).toBe(true);
    expect(statusChanged(base, sig(200, 1000))).toBe(false);
    expect(statusChanged({ ...base, status: -1 }, sig(500, 1000))).toBe(false);
  });

  it("sees a length change only outside the padded range", () => {
    expect(lengthChanged(base, sig(200, 1008))).toBe(false); // within range
    expect(lengthChanged(base, sig(200, 5000))).toBe(true);
    // Not when length was ruled unstable.
    expect(lengthChanged({ ...base, lengthStable: false }, sig(200, 5000))).toBe(false);
  });

  it("names the change, status taking precedence", () => {
    expect(howChanged(base, sig(500, 5000))).toBe("status");
    expect(howChanged(base, sig(200, 5000))).toBe("length");
    expect(howChanged(base, sig(200, 1004))).toBe("");
  });
});

describe("reflected", () => {
  const cands: Candidate[] = [
    { name: "debug", location: "query", value: "zq7fa" },
    { name: "admin", location: "query", value: "zq7fb" },
    { name: "trace", location: "query", value: "zq7fc" },
  ];

  it("returns exactly the names whose value is in the body", () => {
    const body = "<html>welcome zq7fb user</html>";
    expect(reflected(body, "zq7f", cands).map((c) => c.name)).toEqual(["admin"]);
  });

  it("costs one search when nothing reflects (the prefix isn't there)", () => {
    expect(reflected("<html>nothing here</html>", "zq7f", cands)).toEqual([]);
  });

  it("finds several", () => {
    expect(reflected("zq7fa and zq7fc", "zq7f", cands).map((c) => c.name)).toEqual(["debug", "trace"]);
  });
});

describe("canaryValue", () => {
  it("is the prefix plus a base-36 index, unique per index", () => {
    expect(canaryValue("abc", 0)).toBe("abc0");
    expect(canaryValue("abc", 11)).toBe("abcb");
    expect(canaryValue("abc", 1)).not.toBe(canaryValue("abc", 2));
  });
});
