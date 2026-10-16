import { beforeEach, describe, expect, it, mock } from "reproxy/testing";
import { entities, flows, storage, targets } from "reproxy";
import { idle, init, onTargets, setRequestGap } from "../main";

// The plugin keeps a queue and what it has warned about for as long as it
// runs, so each test starts it afresh, as a reload does in the app.
beforeEach(async () => {
  init({ hook: "plugin.on_load", reason: "reload", settings: {} });
  setRequestGap(0);
  await idle();
});

const reply = {
  a: [
    { host: "example.test", ips: [{ ip: "192.0.2.10" }] },
    { host: "shop.example.test", ips: [{ ip: "192.0.2.20", asn: "64500", asn_name: "EXAMPLE-NET", country: "Testland", ptr: "shop.hosting.test" }] },
  ],
  cname: [{ host: "cdn.example.test" }],
  mx: [{ host: "mx.mail.test", ips: [{ ip: "198.51.100.7" }] }],
  ns: [],
  txt: [],
};

function answer(body: unknown = reply, status = 200): void {
  mock.respond("^https://api\\.dnsdumpster\\.com/domain/", {
    status,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function targetsChanged(): Promise<void> {
  await onTargets({ hook: "target.on_changed", targets: targets.list() });
}

describe("onTargets", () => {
  it("looks a new domain target up and lists what isn't in scope as related", async () => {
    mock.settings({ api_key: "test-key-not-real" });
    answer();
    mock.target("domain", "example.test");
    await targetsChanged();

    const sent = mock.sent();
    expect(sent).toHaveLength(1);
    expect(sent[0].url).toBe("https://api.dnsdumpster.com/domain/example.test");
    expect(sent[0].raw).toContain("X-API-Key: test-key-not-real");
    expect(flows.list()).toHaveLength(0); // the key never reaches the traffic list

    // The domain target covers example.test only; its subdomains, the CNAME
    // and the addresses are related. MX records are off by default.
    expect(mock.related().sort()).toEqual(["192.0.2.10", "192.0.2.20", "cdn.example.test", "shop.example.test"]);

    // Names and addresses are hosts of their own, not URLs.
    expect(mock.entities().filter((e) => e.type === "url")).toHaveLength(0);
    const shop = entities.get("shop.example.test");
    expect(shop?.key).toBe("//shop.example.test");
    expect(shop?.type === "host" && shop.addresses).toEqual(["192.0.2.20"]);
    expect(shop?.kv["dnsdumpster.records"]).toBe("A");
    const addr = entities.get("192.0.2.20");
    expect(addr?.type === "host" && addr.ip).toBe(true);
    expect(addr?.kv["dnsdumpster.asn"]).toBe("64500");
    expect(addr?.kv["dnsdumpster.ptr"]).toBe("shop.hosting.test");
    expect(await storage.engagement.get("looked_up")).toEqual(["example.test"]);
  });

  it("looks a domain up once while it is a target, and again once it is added back", async () => {
    mock.settings({ api_key: "test-key-not-real" });
    answer();
    const t = mock.target("domain", "example.test");
    await targetsChanged();
    await targetsChanged();
    expect(mock.sent()).toHaveLength(1);

    await onTargets({ hook: "target.on_changed", targets: [] }); // removed
    await onTargets({ hook: "target.on_changed", targets: [t] }); // added back
    expect(mock.sent()).toHaveLength(2);
  });

  it("looks a wildcard up as its domain, and ignores what names no domain", async () => {
    mock.settings({ api_key: "test-key-not-real" });
    answer();
    mock.target("wildcard", "*.example.test");
    mock.target("ip", "10.0.0.5");
    await targetsChanged();
    expect(mock.sent().map((s) => s.url)).toEqual(["https://api.dnsdumpster.com/domain/example.test"]);
    // The wildcard covers the subdomains but not example.test itself, so
    // that and the addresses are related; the subdomains are in the
    // Explorer all the same.
    expect(mock.related().sort()).toEqual(["192.0.2.10", "192.0.2.20", "example.test"]);
    expect(entities.get("shop.example.test")).toBeDefined();
  });

  it("sends nothing without a key, and doesn't count the domain as done", async () => {
    answer();
    mock.target("domain", "example.test");
    await targetsChanged();
    expect(mock.sent()).toHaveLength(0);
    expect(await storage.engagement.get("looked_up")).toBeUndefined();

    mock.settings({ api_key: "test-key-not-real" });
    await targetsChanged();
    expect(mock.sent()).toHaveLength(1);
  });

  it("leaves a domain to try again when the key is refused", async () => {
    mock.settings({ api_key: "test-key-not-real" });
    answer({ error: "Invalid API key" }, 401);
    mock.target("domain", "example.test");
    await targetsChanged();
    expect(mock.entities().filter((e) => e.origin === "plugin:dnsdumpster")).toHaveLength(0);
    expect(await storage.engagement.get("looked_up")).toBeUndefined();
  });

  it("tries a rate-limited request again, then gives up", async () => {
    mock.settings({ api_key: "test-key-not-real" });
    answer({ error: "Rate limit exceeded" }, 429);
    mock.target("domain", "example.test");
    await targetsChanged();
    expect(mock.sent()).toHaveLength(3);
    expect(await storage.engagement.get("looked_up")).toBeUndefined();
  });

  it("includes mail servers, and leaves addresses out, when the settings say so", async () => {
    mock.settings({ api_key: "test-key-not-real", include_mx: true, include_ips: false });
    answer();
    mock.target("domain", "example.test");
    await targetsChanged();
    expect(mock.related().sort()).toEqual(["cdn.example.test", "mx.mail.test", "shop.example.test"]);
    expect(entities.get("shop.example.test")?.kv["dnsdumpster.ips"]).toBe("192.0.2.20");
    expect(entities.get("192.0.2.20")).toBeUndefined();
  });
});
