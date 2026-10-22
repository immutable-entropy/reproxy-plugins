// What the vulnerability check's own work costs, apart from the network.
// Parsing NVD's answer (which can hold 100+ CVEs) and reducing CISA's KEV
// feed (1700+ entries) both run in goja on the hook's turn, so both have to
// stay well inside the 250 ms budget. The fetching itself is paced and
// awaited, so it doesn't count here.

import { describe, expect, it } from "reproxy/testing";
import { readNvd } from "../src/nvd";
import { reduceKev, kevForProduct } from "../src/kev";

function tick(): Promise<void> {
  return new Promise((done) => setTimeout(done, 0));
}
function ms(fn: () => void): number {
  const start = Date.now();
  fn();
  return Date.now() - start;
}

describe("cost", () => {
  it("parses a large NVD answer quickly", async () => {
    await tick();
    const vulnerabilities = Array.from({ length: 150 }, (_, i) => ({
      cve: {
        id: `CVE-2020-${1000 + i}`,
        published: "2020-01-01T00:00:00.000",
        descriptions: [{ lang: "en", value: "A ".repeat(200) + "vulnerability." }],
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: (i % 10) + 0.5, baseSeverity: "HIGH", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }] },
        weaknesses: [{ description: [{ value: "CWE-79" }] }],
        references: Array.from({ length: 10 }, (_, r) => ({ url: `https://ref.test/${i}/${r}` })),
      },
    }));
    let count = 0;
    const took = ms(() => {
      count = readNvd({ vulnerabilities }, 50)!.length;
    });
    console.log(`readNvd over 150 CVEs (capped to 50): ${took} ms`);
    expect(count).toBe(50);
    expect(took).toBeLessThan(100);
  });

  it("reduces a full-sized KEV feed and matches a product cheaply", async () => {
    await tick();
    const vulnerabilities = Array.from({ length: 1754 }, (_, i) => ({
      cveID: `CVE-2021-${10000 + i}`,
      vendorProject: i % 7 === 0 ? "F5" : "Vendor" + (i % 50),
      product: i % 7 === 0 ? "BIG-IP" : "Product" + (i % 50),
      vulnerabilityName: "Some vulnerability name number " + i,
      dateAdded: "2021-01-01",
      dueDate: "2021-02-01",
      knownRansomwareCampaignUse: i % 2 ? "Known" : "Unknown",
    }));
    let matched = 0;
    const took = ms(() => {
      const index = reduceKev({ vulnerabilities })!;
      matched = kevForProduct(index, { vendor: "f5", product: "big-ip" }).length;
    });
    console.log(`reduceKev over 1754 entries + a product match: ${took} ms`);
    expect(matched).toBeGreaterThan(0);
    expect(took).toBeLessThan(100);
  });
});
