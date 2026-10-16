import { beforeEach, describe, expect, it, mock } from "reproxy/testing";
import { entities, flows, storage, targets } from "reproxy";
import { idle, init, onTargets, setTiming } from "../main";
import { testPEM } from "./fixture";

// The plugin keeps a queue and the services' pacing for as long as it
// runs, so each test starts it afresh, as a reload does in the app.
beforeEach(async () => {
  init({ hook: "plugin.on_load", reason: "reload", settings: {} });
  setTiming(0, 0);
  await idle();
});

// crt.sh knows the shop and the certificate below (which also names
// other-brand.test); ctlogs.dev knows that certificate too, and the API
// host, which crt.sh has missed.
const crtsh = [
  {
    issuer_name: "C=US, O=Example CA, CN=Example Issuing CA 1",
    common_name: "www.example.test",
    name_value: "www.example.test\nexample.test",
    id: 1001,
    not_before: "2026-09-01T00:00:00",
    not_after: "2099-12-01T00:00:00",
    serial_number: "00a1b2c3",
  },
  {
    issuer_name: "C=US, O=Example CA, CN=Example Issuing CA 1",
    common_name: "shop.example.test",
    name_value: "shop.example.test",
    id: 1002,
    not_before: "2026-08-01T00:00:00",
    not_after: "2099-11-01T00:00:00",
    serial_number: "0d0d",
  },
];
const ctlogs = {
  rows: [
    {
      id: "ctl-www", match: "www.example.test", not_before: "2026-09-01T00:00:00Z", not_after: "2099-12-01T00:00:00Z",
      serial_hex: "a1b2c3", issuer: "Example CA", key_algo: "ECDSA P-256", san_count: 3,
    },
    {
      id: "ctl-api", match: "api.example.test", not_before: "2026-07-01T00:00:00Z", not_after: "2099-10-01T00:00:00Z",
      serial_hex: "0e0e", issuer: "Other CA", key_algo: "RSA 2048", san_count: 1,
    },
  ],
  has_next: false,
  next_cursor: "",
};
const ctlogsCert = {
  id: "ctl-www",
  issuer_dn: "CN=Example Issuing CA 1,O=Example CA,C=US",
  san_dns: ["www.example.test", "example.test", "shop.other-brand.test"],
};

function json(pattern: string, body: unknown, status = 200, headers: Record<string, string> = {}): void {
  mock.respond(pattern, { status, headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
}

const crtshSearch = "^https://crt\\.sh/\\?q=";
const crtshCert = "^https://crt\\.sh/\\?d=";
const ctlogsSearch = "^https://api\\.ctlogs\\.dev/v1/subdomains/";
const ctlogsDetail = "^https://api\\.ctlogs\\.dev/v1/cert/";

async function targetsChanged(): Promise<void> {
  await onTargets({ hook: "target.on_changed", targets: targets.list() });
}

describe("onTargets", () => {
  it("asks both services, and merges what they know", async () => {
    json(crtshSearch, crtsh);
    json(ctlogsSearch, ctlogs);
    json(ctlogsDetail, ctlogsCert);
    mock.respond(crtshCert, { body: testPEM });
    mock.target("domain", "example.test");
    await targetsChanged();

    const urls = mock.sent().map((s) => s.url);
    expect(urls).toContain("https://crt.sh/?q=example.test&output=json&deduplicate=Y&exclude=expired");
    expect(urls).toContain("https://api.ctlogs.dev/v1/subdomains/example.test");
    // The shared certificate is read from ctlogs.dev; the shop's, which
    // only crt.sh listed, from crt.sh.
    expect(urls).toContain("https://api.ctlogs.dev/v1/cert/ctl-www");
    expect(urls).toContain("https://crt.sh/?d=1002");
    expect(flows.list()).toHaveLength(0);

    // Each name from either service, and the name the shared certificate
    // adds; all but example.test itself are outside the domain target.
    expect(mock.related().sort()).toEqual(["api.example.test", "shop.example.test", "shop.other-brand.test", "www.example.test"]);
    expect(mock.entities().filter((e) => e.type === "url")).toHaveLength(0);

    const www = entities.get("www.example.test");
    expect(www?.kv["ct.sources"]).toBe("crt.sh, ctlogs.dev");
    expect(www?.kv["ct.issuers"]).toBe("Example CA (Example Issuing CA 1)");
    // Its own certificate, and the shop's, which turned out (read in full
    // from crt.sh) to name it too.
    expect(www?.kv["ct.certificates"]).toBe("2");
    expect(www?.kv["ct.latest_expiry"]).toBe("2099-12-01");
    expect(entities.get("api.example.test")?.kv["ct.sources"]).toBe("ctlogs.dev");
    expect(entities.get("shop.example.test")?.kv["ct.sources"]).toBe("crt.sh");

    const other = entities.get("shop.other-brand.test");
    expect(other?.kv["ct.shares_certificate_with"]).toBe("www.example.test, example.test, shop.example.test");
    const apex = entities.get("//example.test"); // the host, not the domain entity
    expect(apex?.kv["ct.related_domains"]).toBe("other-brand.test");
    expect(apex?.kv["ct.lookup"]).toContain("3 certificates naming 5 hosts");
    expect(await storage.engagement.get("looked_up")).toEqual({ "example.test": ["crt.sh", "ctlogs.dev"] });
  });

  it("looks a domain up once while it is a target, and again once it is added back", async () => {
    json(crtshSearch, crtsh);
    json(ctlogsSearch, ctlogs);
    mock.settings({ related_lookups: 0 });
    const t = mock.target("domain", "example.test");
    await targetsChanged();
    await targetsChanged();
    expect(mock.sent()).toHaveLength(2);

    await onTargets({ hook: "target.on_changed", targets: [] });
    await onTargets({ hook: "target.on_changed", targets: [t] });
    expect(mock.sent()).toHaveLength(4);
  });

  it("records what one service knows when the other is down, and asks both again later", async () => {
    mock.respond(crtshSearch, { status: 502, body: "<html>502 Bad Gateway</html>" });
    json(ctlogsSearch, ctlogs);
    mock.settings({ related_lookups: 0 });
    mock.target("domain", "example.test");
    await targetsChanged();
    expect(mock.sent().filter((s) => s.url.startsWith("https://crt.sh/"))).toHaveLength(3); // tried three times
    expect(entities.get("api.example.test")?.kv["ct.sources"]).toBe("ctlogs.dev");
    expect(entities.get("//example.test")?.kv["ct.lookup"]).toContain("only ctlogs.dev answered");
    expect(await storage.engagement.get("looked_up")).toEqual({ "example.test": ["ctlogs.dev"] });

    await targetsChanged();
    expect(mock.sent().filter((s) => s.url.startsWith("https://api.ctlogs.dev/"))).toHaveLength(2);
  });

  it("leaves names on a shared certificate out", async () => {
    json(crtshSearch, []);
    json(ctlogsSearch, { rows: [{ ...ctlogs.rows[0], san_count: 80 }] });
    mock.target("domain", "example.test");
    await targetsChanged();
    expect(mock.sent().filter((s) => s.url.indexOf("/cert/") >= 0)).toHaveLength(0);
    expect(entities.get("shop.other-brand.test")).toBeUndefined();
    expect(entities.get("www.example.test")).toBeDefined();
  });

  it("stops asking ctlogs.dev once its hourly limit is spent", async () => {
    json(crtshSearch, crtsh);
    json(ctlogsSearch, { error: "hourly limit" }, 429, { "Retry-After": "1800" });
    mock.target("domain", "example.test");
    await targetsChanged();
    expect(mock.sent().filter((s) => s.url.startsWith("https://api.ctlogs.dev/"))).toHaveLength(1);
    expect(entities.get("shop.example.test")?.kv["ct.sources"]).toBe("crt.sh");
  });

  it("sends the ctlogs.dev key only to ctlogs.dev", async () => {
    json(crtshSearch, []);
    json(ctlogsSearch, { rows: [] });
    mock.settings({ ctlogs_api_key: "test-key-not-real" });
    mock.target("wildcard", "*.example.test");
    mock.target("ip", "10.0.0.5");
    await targetsChanged();
    const sent = mock.sent();
    expect(sent).toHaveLength(2);
    expect(sent.find((s) => s.url.startsWith("https://api.ctlogs.dev/"))?.raw).toContain("Authorization: Bearer test-key-not-real");
    expect(sent.find((s) => s.url.startsWith("https://crt.sh/"))?.raw).not.toContain("test-key-not-real");
  });

  it("follows ctlogs.dev's pages up to the setting", async () => {
    json(crtshSearch, []);
    json(ctlogsSearch, { rows: [], has_next: true, next_cursor: "next/page" });
    mock.settings({ ctlogs_pages: 2 });
    mock.target("domain", "example.test");
    await targetsChanged();
    const pages = mock.sent().filter((s) => s.url.startsWith("https://api.ctlogs.dev/"));
    expect(pages.map((s) => s.url)).toEqual([
      "https://api.ctlogs.dev/v1/subdomains/example.test",
      "https://api.ctlogs.dev/v1/subdomains/example.test?after=next%2Fpage",
    ]);
  });
});
