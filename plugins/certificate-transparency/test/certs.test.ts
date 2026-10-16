import { describe, expect, it } from "reproxy/testing";
import {
  detailCandidates, dropExpired, normalSerial, parseDN, readCrtsh, readCtlogs, setSANs, summarize, type Certs,
} from "../src/certs";
import { certName, domainOf, inDomain } from "../src/names";

// The same certificate as each service lists it: crt.sh keeps the serial's
// leading zero byte and gives the issuer's whole DN; ctlogs.dev drops the
// zero and gives the organisation, the key and the SAN count.
const crtRow = {
  issuer_ca_id: 1,
  issuer_name: "C=US, O=Example CA, CN=Example Issuing CA 1",
  common_name: "www.example.test",
  name_value: "www.example.test\nexample.test",
  id: 1001,
  not_before: "2026-09-01T00:00:00",
  not_after: "2099-12-01T00:00:00",
  serial_number: "00a1b2c3",
};
const ctlRow = {
  id: "ctl-0001",
  match: "www.example.test",
  not_before: "2026-09-01T00:00:00Z",
  not_after: "2099-12-01T00:00:00Z",
  serial_hex: "a1b2c3",
  issuer: "Example CA",
  key_algo: "ECDSA P-256",
  san_count: 3,
};

describe("names", () => {
  it("looks up a domain target as it is, and a wildcard as the domain under it", () => {
    expect(domainOf("domain", "Shop.Example.TEST")).toBe("shop.example.test");
    expect(domainOf("wildcard", "*.example.test")).toBe("example.test");
    expect(domainOf("ip", "10.0.0.5")).toBeUndefined();
    expect(domainOf("wildcard", "api-*.example.test")).toBeUndefined();
  });

  it("keeps wildcards and host names, and nothing else", () => {
    expect(certName("*.Example.test.")).toBe("*.example.test");
    expect(certName("admin@example.test")).toBeUndefined();
    expect(certName("192.0.2.1")).toBeUndefined();
    expect(certName("Example Server")).toBeUndefined();
    expect(inDomain("*.example.test", "example.test")).toBe(true);
    expect(inDomain("myexample.test", "example.test")).toBe(false);
  });
});

describe("merging", () => {
  it("makes one certificate of what both services list, with what each adds", () => {
    const certs: Certs = new Map();
    expect(readCrtsh([crtRow], "example.test", certs)).toBe(1);
    expect(readCtlogs({ rows: [ctlRow], has_next: false }, "example.test", certs).count).toBe(1);
    expect(certs.size).toBe(1);
    const c = [...certs.values()][0];
    expect(c.serial).toBe("a1b2c3");
    expect(c.sources).toEqual(["crt.sh", "ctlogs.dev"]);
    expect(c.names).toEqual(["www.example.test", "example.test"]);
    expect(c.issuer).toBe("Example CA");
    expect(c.issuerCN).toBe("Example Issuing CA 1"); // from crt.sh
    expect(c.keyAlgo).toBe("ECDSA P-256"); // from ctlogs.dev
    expect(c.sanCount).toBe(3);
    expect(c.crtshId).toBe(1001);
    expect(c.ctlogsId).toBe("ctl-0001");
  });

  it("keeps a certificate only one service listed", () => {
    const certs: Certs = new Map();
    readCrtsh([crtRow], "example.test", certs);
    readCtlogs({ rows: [{ ...ctlRow, serial_hex: "ffee", match: "api.example.test" }] }, "example.test", certs);
    expect(certs.size).toBe(2);
    expect(summarize(certs, "example.test", 25).has("api.example.test")).toBe(true);
  });

  it("skips crt.sh rows for a name that only ends like the domain", () => {
    const certs: Certs = new Map();
    readCrtsh([{ ...crtRow, common_name: "myexample.test", name_value: "myexample.test" }], "example.test", certs);
    expect(certs.size).toBe(0);
  });

  it("reads ctlogs.dev's cursor only while there are more pages", () => {
    const certs: Certs = new Map();
    expect(readCtlogs({ rows: [], has_next: true, next_cursor: "abc" }, "example.test", certs).next).toBe("abc");
    expect(readCtlogs({ rows: [], has_next: false, next_cursor: "" }, "example.test", certs).next).toBe("");
    expect(readCtlogs("nonsense", "example.test", certs).count).toBe(0);
  });

  it("reads distinguished names in both services' forms", () => {
    expect(parseDN('C=US, O="Example, Inc.", CN=Issuer 2')).toEqual({ C: "US", O: "Example, Inc.", CN: "Issuer 2" });
    expect(parseDN("CN=Issuer 2,O=Example\\, Inc.,C=US")).toEqual({ CN: "Issuer 2", O: "Example, Inc.", C: "US" });
    expect(normalSerial("00:0A:1b")).toBe("a1b");
    expect(normalSerial("not hex")).toBe("");
  });

  it("drops expired certificates", () => {
    const certs: Certs = new Map();
    readCrtsh([crtRow, { ...crtRow, serial_number: "05", not_after: "2020-01-01T00:00:00" }], "example.test", certs);
    dropExpired(certs, Date.parse("2026-10-01T00:00:00Z"));
    expect([...certs.values()].map((c) => c.serial)).toEqual(["a1b2c3"]);
  });
});

describe("related names", () => {
  it("lists names outside the domain only from certificates small enough to say something", () => {
    const certs: Certs = new Map();
    readCtlogs({ rows: [ctlRow, { ...ctlRow, serial_hex: "0bad", match: "cdn.example.test", san_count: 80 }] }, "example.test", certs);
    const [small, shared] = [...certs.values()];
    setSANs(small, ["www.example.test", "example.test", "shop.other-brand.test"], "CN=Example Issuing CA 1,O=Example CA,C=US");
    setSANs(shared, ["cdn.example.test", ...Array.from({ length: 79 }, (_, i) => `customer${i}.unrelated.test`)]);
    const names = summarize(certs, "example.test", 25);
    expect([...names.keys()].sort()).toEqual(["cdn.example.test", "example.test", "shop.other-brand.test", "www.example.test"]);
    const other = names.get("shop.other-brand.test")!;
    expect(other.inDomain).toBe(false);
    expect(other.sharedWith).toEqual(["www.example.test", "example.test"]);
    expect(other.issuers).toEqual(["Example CA (Example Issuing CA 1)"]);
  });

  it("chooses the certificates that may hold unseen names, newest first, one of each shape", () => {
    const certs: Certs = new Map();
    readCtlogs(
      {
        rows: [
          { ...ctlRow, serial_hex: "01", not_before: "2026-01-01T00:00:00Z" }, // older twin of 02
          { ...ctlRow, serial_hex: "02", not_before: "2026-02-01T00:00:00Z" },
          { ...ctlRow, serial_hex: "03", san_count: 1 }, // nothing more to see
          { ...ctlRow, serial_hex: "04", san_count: 80 }, // shared
          { ...ctlRow, serial_hex: "05", match: "a.example.test", not_after: "2020-01-01T00:00:00Z" }, // expired: last
        ],
      },
      "example.test",
      certs,
    );
    readCrtsh([{ ...crtRow, serial_number: "06" }], "example.test", certs); // SAN count unknown
    const now = Date.parse("2026-10-01T00:00:00Z");
    expect(detailCandidates(certs, 25, 10, now).map((c) => c.serial)).toEqual(["6", "2", "5"]);
    expect(detailCandidates(certs, 25, 1, now)).toHaveLength(1);
    expect(detailCandidates(certs, 25, 0, now)).toHaveLength(0);
  });

  it("counts wildcard certificates on the name under them", () => {
    const certs: Certs = new Map();
    readCrtsh([{ ...crtRow, common_name: "*.example.test", name_value: "*.example.test\nexample.test" }], "example.test", certs);
    const s = summarize(certs, "example.test", 25).get("example.test")!;
    expect(s.certificates).toBe(1);
    expect(s.wildcardCertificates).toBe(1);
    expect(s.firstIssued).toBe("2026-09-01");
    expect(s.latestExpiry).toBe("2099-12-01");
  });

  it("names an issuer once, by its fullest name", () => {
    const certs: Certs = new Map();
    readCrtsh([crtRow], "example.test", certs);
    readCtlogs({ rows: [{ ...ctlRow, serial_hex: "0f" }] }, "example.test", certs);
    expect(summarize(certs, "example.test", 25).get("www.example.test")!.issuers).toEqual(["Example CA (Example Issuing CA 1)"]);
  });
});
