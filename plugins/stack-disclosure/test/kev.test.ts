import { describe, expect, it } from "reproxy/testing";
import { kevForProduct, kevPage, kevRecord, reduceKev } from "../src/kev";

// Shaped like the CISA KEV feed.
const feed = {
  title: "CISA Catalog of Known Exploited Vulnerabilities",
  vulnerabilities: [
    {
      cveID: "CVE-2022-1388",
      vendorProject: "F5",
      product: "BIG-IP",
      vulnerabilityName: "F5 BIG-IP Missing Authentication Vulnerability",
      dateAdded: "2022-05-10",
      dueDate: "2022-05-31",
      knownRansomwareCampaignUse: "Known",
    },
    {
      cveID: "CVE-2023-46747",
      vendorProject: "F5",
      product: "BIG-IP Configuration Utility",
      vulnerabilityName: "F5 BIG-IP Configuration Utility Authentication Bypass",
      dateAdded: "2023-10-31",
      dueDate: "2023-11-21",
      knownRansomwareCampaignUse: "Unknown",
    },
    {
      cveID: "CVE-2019-11581",
      vendorProject: "Atlassian",
      product: "Jira Server and Data Center",
      vulnerabilityName: "Atlassian Jira Server-Side Template Injection",
      dateAdded: "2021-11-03",
      dueDate: "2022-05-03",
      knownRansomwareCampaignUse: "Unknown",
    },
  ],
};

describe("reduceKev", () => {
  it("builds a per-CVE record and the entry list", () => {
    const index = reduceKev(feed)!;
    expect(index.entries).toHaveLength(3);
    const rec = kevRecord(index, "CVE-2022-1388")!;
    expect(rec.name).toContain("Missing Authentication");
    expect(rec.added).toBe("2022-05-10");
    expect(rec.due).toBe("2022-05-31");
    expect(rec.ransom).toBe(true);
    expect(kevRecord(index, "CVE-2023-46747")!.ransom).toBe(false);
  });
  it("returns undefined for a feed that isn't one", () => {
    expect(reduceKev({})).toBeUndefined();
    expect(reduceKev("nope")).toBeUndefined();
  });
});

describe("kevForProduct", () => {
  it("matches the vendor exactly and the product as a keyword", () => {
    const index = reduceKev(feed)!;
    // "big-ip" catches both "BIG-IP" and "BIG-IP Configuration Utility".
    expect(kevForProduct(index, { vendor: "f5", product: "big-ip" })).toEqual(["CVE-2022-1388", "CVE-2023-46747"]);
    expect(kevForProduct(index, { vendor: "atlassian", product: "jira" })).toEqual(["CVE-2019-11581"]);
    expect(kevForProduct(index, { vendor: "atlassian", product: "confluence" })).toEqual([]);
  });
});

describe("kevPage", () => {
  it("links to the catalog", () => {
    expect(kevPage()).toBe("https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  });
});
