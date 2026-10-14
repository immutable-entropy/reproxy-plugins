import { describe, it, expect } from "reproxy/testing";
import { DETECTORS, scan, type Options } from "../src/detectors";
import { entropy } from "../src/entropy";
import { redact } from "../src/redact";

const all: Options = {
  detectors: DETECTORS.map((d) => d.id),
  minEntropy: 3.5,
  maxBody: 1 << 20,
  ignoreEmails: ["example.com"],
};

function values(head: string, body: string, side: "request" | "response" = "request", opts = all) {
  return scan(head, body, side, opts).map((h) => `${h.detector}=${h.value}`);
}

describe("passwords and usernames", () => {
  it("finds them in a form login", () => {
    expect(values("POST /login HTTP/1.1", "username=ann%40corp.test&password=hunter2&remember=1")).toEqual([
      "password=hunter2",
      "username=ann@corp.test",
    ]);
  });

  it("finds them in a JSON login", () => {
    const got = values("POST /api/session HTTP/1.1", `{"user": "bob", "newPassword": "s3cr3t!"}`);
    expect(got).toContain("password=s3cr3t!");
    expect(got).toContain("username=bob");
  });

  it("ignores masked passwords", () => {
    expect(values("", `{"password":"********"}`)).toEqual([]);
  });

  it("doesn't report a username with no password beside it", () => {
    expect(values("", `{"username":"carol"}`)).toEqual([]);
  });
});

describe("headers", () => {
  it("decodes Basic credentials", () => {
    expect(values("GET / HTTP/1.1\r\nAuthorization: Basic " + btoa("admin:letmein"), "")).toEqual(["basic_auth=admin:letmein"]);
  });

  it("finds bearer tokens", () => {
    expect(values("GET / HTTP/1.1\r\nauthorization: bearer abc123def456ghi", "")).toEqual(["bearer=abc123def456ghi"]);
  });
});

describe("keys and tokens", () => {
  it("finds well-known key formats", () => {
    const body = [
      "AKIAIOSFODNN7EXAMPLE",
      "ghp_" + "a".repeat(36),
      "xoxb-1234567890-abcdef",
      "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
      "AIza" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",
    ].join(" ");
    const got = values("", body, "response");
    expect(got).toHaveLength(5);
    expect(got[0]).toBe("aws_key=AKIAIOSFODNN7EXAMPLE");
  });

  it("finds JWTs", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig_nature";
    expect(values("", `{"token":"${jwt}"}`, "response")).toContain("jwt=" + jwt);
  });

  it("only flags generic keys that look random", () => {
    expect(values("", `api_key=aaaaaaaaaaaaaaaaaaaa`)).toEqual([]);
    expect(values("", `api_key=Zx9Qm2Lw7Vb4Np8Kr3Ty`)).toEqual(["api_key=Zx9Qm2Lw7Vb4Np8Kr3Ty"]);
  });

  it("finds private keys", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----";
    expect(values("", "key: " + pem, "response")).toEqual(["private_key=" + pem]);
  });
});

describe("email addresses", () => {
  it("skips ignored domains and asset names", () => {
    expect(values("", "contact dev@corp.test or a@example.com, see logo@2x.png", "response")).toEqual(["email=dev@corp.test"]);
  });
});

describe("settings", () => {
  it("runs only the enabled detectors", () => {
    const opts = { ...all, detectors: ["jwt"] };
    expect(values("", "AKIAIOSFODNN7EXAMPLE", "response", opts)).toEqual([]);
  });
});

describe("helpers", () => {
  it("measures entropy", () => {
    expect(entropy("aaaa")).toBe(0);
    expect(entropy("abcd")).toBe(2);
  });

  it("redacts for the log", () => {
    expect(redact("short")).toBe("*****");
    expect(redact("hunter2hunter2")).toBe("hunt…r2 (14 chars)");
  });
});
