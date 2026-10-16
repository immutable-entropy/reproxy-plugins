import { beforeEach, describe, expect, it, mock } from "reproxy/testing";
import { flows, storage, targets } from "reproxy";
import { load, setRetry } from "../main";

// The plugin remembers what it has recorded and asked for as long as it
// runs, so each test starts it afresh, as a reload does in the app, and
// without the osv.dev answers it keeps in storage.
beforeEach(async () => {
  load();
  setRetry(0);
  await storage.delete("osv_cache");
});

const osv = "^https://api\\.osv\\.dev/v1/query$";
const advisories = {
  vulns: [
    {
      id: "GHSA-test-0001",
      summary: "Potential XSS in the test library",
      aliases: ["CVE-0000-0001"],
      database_specific: { severity: "MODERATE" },
      affected: [{ package: { ecosystem: "npm", name: "jquery" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "3.5.0" }] }] }],
    },
    {
      id: "GHSA-test-0002",
      summary: "Prototype pollution in the test library.",
      database_specific: { severity: "HIGH" },
      affected: [{ package: { ecosystem: "npm", name: "jquery" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "3.4.0" }] }] }],
    },
  ],
};

function answer(body: unknown, status = 200): void {
  mock.respond(osv, { status, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

// A flow to app.test carries its target's ID, as the proxy gives it.
const script = (url: string, body = "", headers: Record<string, string> = {}) => ({
  url,
  targetId: url.startsWith("https://app.test/") ? targets.list().find((t) => t.value === "app.test")?.id ?? "" : "",
  requestHeaders: headers,
  responseHeaders: { "Content-Type": "application/javascript" },
  responseBody: body,
});

const jquery = "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(a,b){}";

describe("in-scope scripts", () => {
  it("records the version, and each advisory with its osv.dev link", async () => {
    mock.target("domain", "app.test");
    answer(advisories);
    const flow = mock.flow(script("https://app.test/js/app.js", jquery));
    expect(await mock.dispatch("traffic.on_response_received", flow)).toBe(1);

    const sent = mock.sent();
    expect(sent).toHaveLength(1);
    expect(sent[0].method).toBe("POST");
    expect(sent[0].raw).toContain('{"version":"1.12.4","package":{"name":"jquery","ecosystem":"npm"}}');
    expect(sent[0].raw).not.toContain("app.test"); // nothing about the target leaves
    expect(flows.list().filter((f) => f.host === "api.osv.dev")).toHaveLength(0);

    const all = mock.findings();
    const lib = all.find((f) => f.value === "jquery@1.12.4")!;
    expect(lib.types).toEqual(["js-library"]);
    expect(lib.links[0].flowId).toBe(flow.id);
    expect(lib.links[0].location).toBe("response_body");
    expect(lib.notes).toContain("osv.dev lists 2 known vulnerabilities");
    expect(lib.notes).toContain("https://osv.dev/vulnerability/GHSA-test-0001");
    expect(lib.notes).toContain("Upgrading to 3.5.0 or later fixes all of them.");

    const vuln = all.find((f) => f.value === "GHSA-test-0001 in jquery@1.12.4")!;
    expect(vuln.types).toEqual(["js-vulnerability"]);
    expect(vuln.notes).toContain("jQuery 1.12.4 is affected by GHSA-test-0001 (CVE-0000-0001): Potential XSS in the test library.");
    expect(vuln.notes).toContain("It is fixed in jQuery 3.5.0.");
    expect(vuln.notes).toContain("Details: https://osv.dev/vulnerability/GHSA-test-0001");
    const fields = Object.fromEntries(vuln.fields.map((f) => [f.key, f.value]));
    expect(fields["osv.dev"]).toBe("https://osv.dev/vulnerability/GHSA-test-0001");
    expect(fields.severity).toBe("MODERATE");
    expect(fields.fixed_in).toBe("3.5.0");
    expect(all.find((f) => f.value === "GHSA-test-0002 in jquery@1.12.4")).toBeDefined();
    expect(all).toHaveLength(3);
  });

  it("asks osv.dev once per version, and merges each script into the same findings", async () => {
    mock.target("domain", "app.test");
    answer(advisories);
    await mock.dispatch("traffic.on_response_received", script("https://app.test/a.js", jquery));
    await mock.dispatch("traffic.on_response_received", script("https://app.test/b.js", jquery));
    await mock.dispatch("traffic.on_response_received", script("https://app.test/a.js", jquery));
    expect(mock.sent()).toHaveLength(1);
    const lib = mock.findings().find((f) => f.value === "jquery@1.12.4")!;
    expect(lib.links).toHaveLength(2);
    expect(lib.notes.split("osv.dev lists")).toHaveLength(2); // the notes weren't repeated
    expect(mock.findings()).toHaveLength(3);
  });

  it("says so when osv.dev knows of nothing", async () => {
    mock.target("domain", "app.test");
    answer({});
    await mock.dispatch("traffic.on_response_received", script("https://app.test/js/jquery-3.7.1.min.js"));
    const found = mock.findings();
    expect(found.map((f) => f.value)).toEqual(["jquery@3.7.1"]);
    expect(found[0].notes).toContain("osv.dev lists no known vulnerabilities in this version.");
    expect(found[0].links[0].detail).toBe("found by file name");
  });

  it("doesn't look up a version it only knows part of", async () => {
    mock.target("domain", "app.test");
    answer(advisories);
    await mock.dispatch("traffic.on_response_received", script("https://app.test/js/jquery-1.12.min.js"));
    expect(mock.sent()).toHaveLength(0);
    expect(mock.findings()[0].notes).toContain("Only part of the version is known (1.12)");
  });

  it("records the version when osv.dev is down, and asks again next time", async () => {
    mock.target("domain", "app.test");
    answer({ error: "unavailable" }, 503);
    await mock.dispatch("traffic.on_response_received", script("https://app.test/a.js", jquery));
    expect(mock.sent()).toHaveLength(3); // tried three times
    expect(mock.findings().map((f) => f.value)).toEqual(["jquery@1.12.4"]);
    expect(mock.findings()[0].notes).toContain("couldn't be asked");
    await mock.dispatch("traffic.on_response_received", script("https://app.test/a.js", jquery));
    expect(mock.sent()).toHaveLength(6);
  });

  it("sends nothing when osv.dev lookups are off", async () => {
    mock.target("domain", "app.test");
    mock.settings({ query_osv: false });
    await mock.dispatch("traffic.on_response_received", script("https://app.test/a.js", jquery));
    expect(mock.sent()).toHaveLength(0);
    expect(mock.findings()[0].notes).toContain("turned off");
  });

  it("is not called for what isn't a script, nor for an error page", async () => {
    mock.target("domain", "app.test");
    expect(
      await mock.dispatch("traffic.on_response_received", {
        url: "https://app.test/",
        responseHeaders: { "Content-Type": "text/html" },
        responseBody: jquery,
      }),
    ).toBe(0);
    expect(await mock.dispatch("traffic.on_response_received", { ...script("https://app.test/a.js", jquery), status: 404 })).toBe(0);
  });
});

describe("scripts from public CDNs", () => {
  it("checks a CDN script a target's page asked for", async () => {
    mock.target("domain", "app.test");
    answer({});
    const flow = script("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js", "", { Referer: "https://app.test/login" });
    expect(await mock.dispatch("traffic.on_response_received", flow)).toBe(1);
    const lib = mock.findings()[0];
    expect(lib.value).toBe("jquery@3.7.1");
    expect(lib.links[0].detail).toBe("found by URL (cdnjs.cloudflare.com); loaded by https://app.test/login");
  });

  it("ignores a CDN script loaded by any other site", async () => {
    mock.target("domain", "app.test");
    answer({});
    await mock.dispatch(
      "traffic.on_response_received",
      script("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js", "", { Referer: "https://elsewhere.test/" }),
    );
    await mock.dispatch("traffic.on_response_received", script("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"));
    expect(mock.findings()).toHaveLength(0);
    expect(mock.sent()).toHaveLength(0);
  });

  it("isn't called for scripts from other hosts no target covers", async () => {
    mock.target("domain", "app.test");
    expect(
      await mock.dispatch("traffic.on_response_received", script("https://tracker.test/jquery-1.12.4.js", jquery, { Referer: "https://app.test/" })),
    ).toBe(0);
  });
});
