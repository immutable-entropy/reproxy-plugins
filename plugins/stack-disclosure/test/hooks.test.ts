import { beforeEach, describe, expect, it, mock } from "reproxy/testing";
import { storage } from "reproxy";
import { load, scanResponse, setPace, setRetry } from "../main";

// The plugin starts afresh each test (as a reload does), without the NVD
// answers or the KEV index it keeps in storage between runs.
beforeEach(async () => {
  load();
  setPace(0); // no pacing between NVD requests in tests
  setRetry(0); // no backoff before a retry
  await storage.delete("nvd_cache");
  await storage.delete("kev_index");
});

/** The detector ids a response's findings tripped. */
function detectors(): string[] {
  return mock.findings().map((f) => f.fields.find((x) => x.key === "detector")?.value ?? "");
}

describe("scanResponse", () => {
  it("records a disclosure readable, never hidden", async () => {
    const flow = mock.flow({
      url: "https://app.test/",
      responseHeaders: { "Content-Type": "text/html", "X-Powered-By": "PHP/7.4.3" },
      responseBody: "<p>hi</p>",
    });
    expect(await mock.dispatch("traffic.on_response_received", flow)).toBe(1);
    const [f] = mock.findings();
    expect(f.types).toEqual(["disclosure"]);
    expect(f.value).toBe("X-Powered-By: PHP/7.4.3");
    expect(f.hidden).toBe(false);
    expect(f.links[0].location).toBe("response_header");
  });

  it("records a disclosure once per host, with notes that merge", async () => {
    const response = (url: string) => ({
      url,
      responseHeaders: { "Content-Type": "text/html", Server: "Apache/2.4.41 (Ubuntu)" },
      responseBody: "<p>hello</p>",
    });
    await mock.dispatch("traffic.on_response_received", response("https://app.test/a"));
    await mock.dispatch("traffic.on_response_received", response("https://app.test/b"));
    await mock.dispatch("traffic.on_response_received", response("https://api.app.test/c"));
    const found = mock.findings();
    expect(found).toHaveLength(1);
    expect(found[0].value).toBe("Server: Apache/2.4.41 (Ubuntu)");
    expect(found[0].links.map((l) => l.url)).toEqual(["https://app.test/a", "https://api.app.test/c"]);
    expect(found[0].notes.split("Web server banner")).toHaveLength(2); // written once
    expect(found[0].notes).toContain("ServerTokens Prod");
  });

  it("drops bare banners when only versions are wanted", async () => {
    mock.settings({ versions_only: true });
    await mock.dispatch("traffic.on_response_received", {
      url: "https://app.test/",
      responseHeaders: { Server: "nginx", "X-Powered-By": "PHP/8.1.2", "X-Backend-Server": "web-03" },
    });
    expect(detectors()).toEqual(["tech_header", "internal_host"]);
  });

  it("skips a detector by id", async () => {
    mock.settings({ skip_detectors: ["server_banner"] });
    await mock.dispatch("traffic.on_response_received", {
      url: "https://app.test/",
      responseHeaders: { Server: "Apache/2.4.41", "X-Backend-Server": "web-03" },
    });
    expect(detectors()).toEqual(["internal_host"]);
  });
});

// ---- The vulnerability check -------------------------------------------------

/** An NVD CVE entry with a CVSS v3.1 score. */
function cve(id: string, score: number, severity: string) {
  return {
    cve: {
      id,
      descriptions: [{ lang: "en", value: `${id} summary.` }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: score, baseSeverity: severity, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }] },
    },
  };
}
const json = (body: unknown) => ({ status: 200, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const nvdReply = (cves: unknown[]) => json({ vulnerabilities: cves });
const kevReply = (entries: unknown[]) => json({ vulnerabilities: entries });

const APACHE = { url: "https://app.test/", responseHeaders: { Server: "Apache/2.4.41", "Content-Type": "text/html" } };
const vulnFindings = () => mock.findings().filter((f) => f.types[0].indexOf("vuln") === 0);
const field = (f: ReturnType<typeof mock.findings>[number], key: string) => f.fields.find((x) => x.key === key);

describe("the vulnerability check", () => {
  it("sends nothing and records only disclosures when it is off (the default)", async () => {
    await mock.dispatch("traffic.on_response_received", APACHE);
    expect(mock.sent()).toHaveLength(0);
    expect(vulnFindings()).toHaveLength(0);
    expect(mock.findings().every((f) => f.types[0] === "disclosure")).toBe(true);
  });

  it("records a CVE graded by its CVSS score and flags the one in CISA KEV", async () => {
    mock.settings({ check_vulnerabilities: true });
    mock.respond("known_exploited_vulnerabilities", kevReply([
      { cveID: "CVE-2021-0001", vendorProject: "Apache", product: "HTTP Server", vulnerabilityName: "RCE", dateAdded: "2021-03-01", dueDate: "2021-03-21", knownRansomwareCampaignUse: "Known" },
    ]));
    mock.respond("http_server:2\\.4\\.41", nvdReply([cve("CVE-2021-0001", 9.8, "CRITICAL"), cve("CVE-2021-0002", 5.3, "MEDIUM")]));

    await mock.dispatch("traffic.on_response_received", APACHE);

    const vulns = vulnFindings();
    expect(vulns.map((f) => f.value)).toContain("CVE-2021-0001 in Apache HTTP Server 2.4.41");
    const crit = vulns.find((f) => f.value.indexOf("0001") >= 0)!;
    expect(crit.types).toEqual(["vuln-critical"]);
    expect(field(crit, "cvss")!.value).toContain("9.8");
    expect(field(crit, "nvd")!.value).toBe("https://nvd.nist.gov/vuln/detail/CVE-2021-0001");
    expect(field(crit, "kev")).toBeDefined(); // cross-referenced against KEV
    expect(crit.notes).toContain("exploited in the wild");

    const med = vulns.find((f) => f.value.indexOf("0002") >= 0)!;
    expect(med.types).toEqual(["vuln-medium"]);
    expect(field(med, "kev")).toBeUndefined();
  });

  it("drops a CVE below the CVSS floor", async () => {
    mock.settings({ check_vulnerabilities: true, use_kev: false, min_cvss: 7 });
    mock.respond("http_server", nvdReply([cve("CVE-A", 9.8, "CRITICAL"), cve("CVE-B", 5.3, "MEDIUM")]));
    await mock.dispatch("traffic.on_response_received", APACHE);
    const vulns = vulnFindings();
    expect(vulns).toHaveLength(1);
    expect(vulns[0].value).toContain("CVE-A");
  });

  it("reports a product NVD can't version-match (BigIP) from CISA KEV", async () => {
    mock.settings({ check_vulnerabilities: true });
    mock.respond("known_exploited_vulnerabilities", kevReply([
      { cveID: "CVE-2022-1388", vendorProject: "F5", product: "BIG-IP", vulnerabilityName: "F5 BIG-IP Missing Authentication", dateAdded: "2022-05-10", dueDate: "2022-05-31", knownRansomwareCampaignUse: "Known" },
      { cveID: "CVE-2023-46747", vendorProject: "F5", product: "BIG-IP Configuration Utility", vulnerabilityName: "Auth bypass", dateAdded: "2023-10-31", dueDate: "2023-11-21", knownRansomwareCampaignUse: "Unknown" },
    ]));
    await mock.dispatch("traffic.on_response_received", { url: "https://app.test/", responseHeaders: { Server: "BigIP 16.1.0" } });

    const vulns = vulnFindings();
    expect(vulns).toHaveLength(1);
    expect(vulns[0].types).toEqual(["vuln-kev"]);
    expect(vulns[0].value).toBe("F5 BIG-IP in CISA KEV");
    expect(vulns[0].notes).toContain("confirm whether the running version");
    expect(field(vulns[0], "count")!.value).toBe("2");
    // No NVD request: BigIP has no single CPE, so only the KEV feed is fetched.
    expect(mock.sent().every((s) => /known_exploited/.test(s.url))).toBe(true);
  });

  it("skips a two-part version unless full versions aren't required", async () => {
    mock.settings({ check_vulnerabilities: true, use_kev: false });
    mock.respond("http_server", nvdReply([cve("CVE-A", 9.8, "CRITICAL")]));
    await mock.dispatch("traffic.on_response_received", { url: "https://app.test/a", responseHeaders: { Server: "Apache/2.4" } });
    expect(mock.sent()).toHaveLength(0);

    mock.settings({ check_vulnerabilities: true, use_kev: false, require_full_version: false });
    await mock.dispatch("traffic.on_response_received", { url: "https://app.test/b", responseHeaders: { Server: "Apache/2.4" } });
    expect(mock.sent().length).toBeGreaterThan(0);
  });

  it("asks NVD once for a version seen on many responses", async () => {
    mock.settings({ check_vulnerabilities: true, use_kev: false });
    mock.respond("http_server:2\\.4\\.41", nvdReply([cve("CVE-A", 9.8, "CRITICAL")]));
    for (const p of ["/a", "/b", "/c"]) {
      await mock.dispatch("traffic.on_response_received", { url: "https://app.test" + p, responseHeaders: { Server: "Apache/2.4.41" } });
    }
    expect(mock.sent().filter((s) => /http_server/.test(s.url))).toHaveLength(1);
    expect(vulnFindings()).toHaveLength(1);
  });
});
