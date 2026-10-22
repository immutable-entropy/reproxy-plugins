import { describe, expect, it } from "reproxy/testing";
import { band, nvdPage, nvdUrl, readNvd, typeFor } from "../src/nvd";

// Shaped like the NVD 2.0 API: { vulnerabilities: [ { cve: {...} }, ... ] }.
const reply = {
  vulnerabilities: [
    {
      cve: {
        id: "CVE-2021-23017",
        published: "2021-05-26T19:15:00.000",
        descriptions: [
          { lang: "es", value: "no" },
          { lang: "en", value: "A security issue in nginx resolver was identified, which might allow an attacker to overwrite memory" },
        ],
        metrics: {
          cvssMetricV31: [
            {
              cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
            },
          ],
        },
        weaknesses: [{ description: [{ value: "CWE-787" }, { value: "NVD-CWE-noinfo" }] }],
        references: [{ url: "https://nginx.org/advisory.html" }, { url: "https://example.test/dup" }, { url: "https://example.test/dup" }],
      },
    },
    {
      cve: {
        id: "CVE-2019-20372",
        descriptions: [{ lang: "en", value: "low thing." }],
        metrics: { cvssMetricV2: [{ baseSeverity: "MEDIUM", cvssData: { baseScore: 5.3, vectorString: "AV:N/AC:L/Au:N/C:N/I:P/A:N" } }] },
      },
    },
    {
      cve: { id: "CVE-2000-0000", descriptions: [{ lang: "en", value: "no score" }] },
    },
  ],
};

describe("nvdUrl / nvdPage", () => {
  it("builds the virtualMatchString query and the detail page", () => {
    expect(nvdUrl("a:apache:http_server", "2.4.41", 50)).toBe(
      "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:apache:http_server:2.4.41&resultsPerPage=50",
    );
    expect(nvdPage("CVE-2021-23017")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2021-23017");
  });
});

describe("band / typeFor", () => {
  it("bands by the CVSS v3 thresholds", () => {
    expect(band(9.8)).toBe("critical");
    expect(band(7.0)).toBe("high");
    expect(band(4.0)).toBe("medium");
    expect(band(3.9)).toBe("low");
    expect(typeFor(9.8)).toBe("vuln-critical");
    expect(typeFor(-1)).toBe("vuln-low");
  });
});

describe("readNvd", () => {
  it("keeps what a finding needs, most severe first", () => {
    const got = readNvd(reply, 50)!;
    expect(got.map((c) => c.id)).toEqual(["CVE-2021-23017", "CVE-2019-20372", "CVE-2000-0000"]);
    const top = got[0];
    expect(top.score).toBe(9.8);
    expect(top.severity).toBe("CRITICAL");
    expect(top.vector).toContain("CVSS:3.1/");
    expect(top.published).toBe("2021-05-26");
    expect(top.summary).toContain("nginx resolver");
    expect(top.cwes).toEqual(["CWE-787"]); // the NVD-CWE-noinfo pseudo-entry is dropped
    expect(top.refs).toEqual(["https://nginx.org/advisory.html", "https://example.test/dup"]); // de-duplicated
  });
  it("reads a v2 metric's severity from the metric, not cvssData", () => {
    const v2 = readNvd(reply, 50)!.find((c) => c.id === "CVE-2019-20372")!;
    expect(v2.score).toBe(5.3);
    expect(v2.severity).toBe("MEDIUM");
  });
  it("marks a CVE with no metric as unscored", () => {
    const none = readNvd(reply, 50)!.find((c) => c.id === "CVE-2000-0000")!;
    expect(none.score).toBe(-1);
    expect(none.severity).toBe("UNKNOWN");
  });
  it("honours the cap", () => {
    expect(readNvd(reply, 1)).toHaveLength(1);
  });
  it("reads an empty answer as nothing, and nonsense as no answer", () => {
    expect(readNvd({}, 50)).toEqual([]);
    expect(readNvd("<html>", 50)).toBeUndefined();
    expect(readNvd({ vulnerabilities: "x" }, 50)).toBeUndefined();
  });
});
