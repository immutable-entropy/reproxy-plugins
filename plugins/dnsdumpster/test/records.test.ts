import { describe, expect, it } from "reproxy/testing";
import { domainOf, emptyLookup, isHostName, isIP, readPage } from "../src/records";

const all = { cname: true, mx: true, ns: true };

describe("domainOf", () => {
  it("looks up a domain target as it is, and a wildcard as the domain under it", () => {
    expect(domainOf("domain", "Shop.Example.TEST")).toBe("shop.example.test");
    expect(domainOf("wildcard", "*.example.test")).toBe("example.test");
  });

  it("names no domain for addresses, ranges, regexes and other globs", () => {
    expect(domainOf("ip", "10.0.0.5")).toBeUndefined();
    expect(domainOf("cidr", "10.0.0.0/8")).toBeUndefined();
    expect(domainOf("regex", ".*\\.example\\.test")).toBeUndefined();
    expect(domainOf("wildcard", "api-*.example.test")).toBeUndefined();
    expect(domainOf("domain", "localhost")).toBeUndefined();
    expect(domainOf("domain", "10.0.0.5")).toBeUndefined();
  });
});

describe("readPage", () => {
  const reply = {
    a: [
      {
        host: "www.example.test",
        ips: [{ ip: "192.0.2.10", asn: "64500", asn_name: "EXAMPLE-NET", country: "Testland", ptr: "web.example.test" }],
      },
      { host: "API.example.test.", ips: [{ ip: "192.0.2.10" }, { ip: "2001:db8::1" }] },
    ],
    cname: [{ host: "cdn.example.test" }, "assets.example.test"],
    mx: [{ host: "mx.mail.test", ips: [{ ip: "198.51.100.7" }] }],
    ns: [{ host: "ns1.dns.test", ips: [] }],
    txt: ["v=spf1 -all"],
    total_a_recs: 2,
  };

  it("reads names and addresses, and which names resolve to each address", () => {
    const got = emptyLookup();
    expect(readPage(reply, all, got)).toBe(9); // 6 names, 3 addresses
    expect([...got.names.keys()]).toEqual([
      "www.example.test", "api.example.test", "cdn.example.test", "assets.example.test", "mx.mail.test", "ns1.dns.test",
    ]);
    expect(got.names.get("api.example.test")?.ips).toEqual(["192.0.2.10", "2001:db8::1"]);
    const web = got.ips.get("192.0.2.10");
    expect(web?.asn).toBe("64500");
    expect(web?.ptr).toBe("web.example.test");
    expect(web?.names).toEqual(["www.example.test", "api.example.test"]);
  });

  it("keeps only the record types asked for, and always A records", () => {
    const got = emptyLookup();
    readPage(reply, { cname: false, mx: false, ns: false }, got);
    expect([...got.names.keys()]).toEqual(["www.example.test", "api.example.test"]);
    expect(got.ips.has("198.51.100.7")).toBe(false);
  });

  it("merges pages, and counts only what a page added", () => {
    const got = emptyLookup();
    readPage(reply, all, got);
    expect(readPage(reply, all, got)).toBe(0);
    expect(readPage({ a: [{ host: "new.example.test" }] }, all, got)).toBe(1);
  });

  it("skips what isn't a name or an address", () => {
    const got = emptyLookup();
    readPage({ a: [{ host: "not a host", ips: [{ ip: "999.1.1.1" }] }, { host: 42 }, null, { host: "ok.example.test", ips: "x" }] }, all, got);
    expect([...got.names.keys()]).toEqual(["ok.example.test"]);
    expect(got.ips.size).toBe(0);
    expect(readPage("nonsense", all, got)).toBe(0);
  });
});

describe("addresses", () => {
  it("tells names from addresses", () => {
    expect(isIP("192.0.2.1")).toBe(true);
    expect(isIP("2001:db8::1")).toBe(true);
    expect(isHostName("192.0.2.1")).toBe(false);
    expect(isHostName("_dmarc.example.test")).toBe(true);
  });
});
