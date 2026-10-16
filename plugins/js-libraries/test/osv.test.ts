import { describe, expect, it } from "reproxy/testing";
import { compare, fixedFor, osvUrl, readAnswer } from "../src/osv";

const affected = [
  {
    package: { ecosystem: "npm", name: "jquery" },
    ranges: [{ type: "SEMVER", events: [{ introduced: "2.0.0" }, { fixed: "3.5.0" }] }],
  },
  {
    package: { ecosystem: "npm", name: "jquery" },
    ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.9.0" }, { introduced: "4.0.0-beta" }, { fixed: "4.0.0" }] }],
  },
];

describe("readAnswer", () => {
  it("keeps what a finding needs, most severe first, and drops withdrawn advisories", () => {
    const reply = {
      vulns: [
        { id: "GHSA-test-0002", summary: "Low thing", database_specific: { severity: "LOW" } },
        {
          id: "GHSA-test-0001",
          summary: "XSS in the test library",
          aliases: ["CVE-0000-0001", "GHSA-test-0001"],
          database_specific: { severity: "moderate" },
          severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N" }],
          affected,
          published: "2020-04-29T22:18:55Z",
        },
        { id: "GHSA-test-0003", summary: "Gone", withdrawn: "2021-01-01T00:00:00Z" },
        { id: "GHSA-test-0004", details: "First line of details. More.\nSecond." },
      ],
    };
    const got = readAnswer(reply, "jquery", "2.2.4")!;
    expect(got.map((v) => v.id)).toEqual(["GHSA-test-0001", "GHSA-test-0002", "GHSA-test-0004"]);
    expect(got[0].aliases).toEqual(["CVE-0000-0001"]);
    expect(got[0].severity).toBe("MODERATE");
    expect(got[0].cvss).toContain("CVSS:3.1/");
    expect(got[0].fixed).toBe("3.5.0");
    expect(got[0].published).toBe("2020-04-29");
    expect(got[2].summary).toBe("First line of details.");
  });

  it("reads an empty answer as nothing known, and nonsense as no answer", () => {
    expect(readAnswer({}, "jquery", "3.7.1")).toEqual([]);
    expect(readAnswer("<html>", "jquery", "3.7.1")).toBeUndefined();
    expect(readAnswer({ vulns: "x" }, "jquery", "3.7.1")).toBeUndefined();
  });
});

describe("fixedFor", () => {
  it("finds the release closing the range a version is in", () => {
    expect(fixedFor(affected, "jquery", "1.8.3")).toBe("1.9.0");
    expect(fixedFor(affected, "jquery", "3.4.1")).toBe("3.5.0");
    expect(fixedFor(affected, "jquery", "4.0.0-rc.1")).toBe("4.0.0");
    expect(fixedFor(affected, "jquery", "3.5.0")).toBe("");
    expect(fixedFor(affected, "jquery-ui", "1.8.3")).toBe("");
  });
});

describe("compare", () => {
  it("orders versions as semver does", () => {
    expect(compare("1.10.0", "1.9.9")).toBeGreaterThan(0);
    expect(compare("3.0.0-rc.1", "3.0.0")).toBeLessThan(0);
    expect(compare("3.0.0-beta", "3.0.0-rc")).toBeLessThan(0);
    expect(compare("3.0.0-rc.2", "3.0.0-rc.10")).toBeLessThan(0);
    expect(compare("2.0.0", "2.0.0")).toBe(0);
  });

  it("links to osv.dev", () => {
    expect(osvUrl("GHSA-test-0001")).toBe("https://osv.dev/vulnerability/GHSA-test-0001");
  });
});
