import { describe, it, expect } from "reproxy/testing";
import { compose, scan } from "../src/pattern";

const set = compose("test", [
  { id: "pair", pattern: `\\b(\\w+)=(\\w+)\\b` },
  { id: "tag", pattern: `#(\\w+)` },
  { id: "bang", pattern: `!!` },
]);

describe("compose", () => {
  it("carries no capturing groups of its own", () => {
    expect(set.source).toBe(`(?:\\b(\\w+)=(\\w+)\\b)|(?:#(\\w+))|(?:!!)`);
  });

  it("gives every branch its own groups back", () => {
    const got = scan(set, "a=1 #tag !!", 100);
    expect(got.map((m) => m.id)).toEqual(["pair", "tag", "bang"]);
    expect(got[0].groups).toEqual(["a", "1"]);
    expect(got[1].groups).toEqual(["tag"]);
    expect(got[2].groups).toEqual([]);
    expect(got[2].match).toBe("!!");
  });

  it("reads the whole text in one pass, in the order the text runs", () => {
    expect(scan(set, "#one a=2 #three", 100).map((m) => m.match)).toEqual(["#one", "a=2", "#three"]);
  });

  it("names the branch the hit started with, not one inside it", () => {
    // "b=2" holds "=2", and the tag branch could match inside a longer hit:
    // the leftmost, longest branch is the one that found it.
    const nested = compose("nested", [
      { id: "inner", pattern: `\\d+` },
      { id: "outer", pattern: `#\\d+-\\d+` },
    ]);
    expect(scan(nested, "#12-34", 10).map((m) => m.id)).toEqual(["outer"]);
  });

  it("stops at the cap", () => {
    expect(scan(set, "a=1 b=2 c=3", 2)).toHaveLength(2);
  });

  it("is quiet about an empty set", () => {
    expect(scan(compose("none", []), "anything", 10)).toEqual([]);
  });
});
