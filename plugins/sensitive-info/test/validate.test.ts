import { describe, it, expect } from "reproxy/testing";
import {
  decodeBase64,
  decodeForm,
  digits,
  isPlaceholder,
  looksLikeHash,
  luhn,
  plausibleDate,
  plausiblePhone,
  plausibleSsn,
  validIban,
} from "../src/validate";
import { entropy } from "../src/entropy";
import { redact } from "../src/redact";

describe("placeholders", () => {
  it("knows a value that holds nothing", () => {
    for (const v of ["", "null", "undefined", "N/A", "********", "•••• 1234", "{{token}}", "${PASSWORD}", "<your key>", "your_api_key", "changeme", ":password"]) {
      expect(isPlaceholder(v)).toBe(true);
    }
  });

  it("keeps the weak passwords a test environment really uses", () => {
    for (const v of ["test", "password", "hunter2", "secret", "123456", "admin"]) {
      expect(isPlaceholder(v)).toBe(false);
    }
  });
});

describe("card numbers", () => {
  it("checks the Luhn digit", () => {
    expect(luhn("4111111111111111")).toBe(true);
    expect(luhn("4111 1111 1111 1111")).toBe(true);
    expect(luhn("378282246310005")).toBe(true);
    expect(luhn("4111111111111112")).toBe(false);
    expect(luhn("411111")).toBe(false);
  });
});

describe("IBANs", () => {
  it("checks the mod-97 checksum", () => {
    expect(validIban("GB82 WEST 1234 5698 7654 32")).toBe(true);
    expect(validIban("DE89370400440532013000")).toBe(true);
    expect(validIban("GB82WEST12345698765433")).toBe(false);
    expect(validIban("NOTANIBAN")).toBe(false);
  });
});

describe("other identifiers", () => {
  it("rejects the Social Security numbers that can't be issued", () => {
    expect(plausibleSsn("234-56-7890")).toBe(true);
    expect(plausibleSsn("000-12-3456")).toBe(false);
    expect(plausibleSsn("666-12-3456")).toBe(false);
    expect(plausibleSsn("901-12-3456")).toBe(false);
    expect(plausibleSsn("234-00-7890")).toBe(false);
    expect(plausibleSsn("123-45-6789")).toBe(false); // the example everyone uses
  });

  it("knows a telephone number from a counter", () => {
    expect(plausiblePhone("+1 415 555 0123")).toBe(true);
    expect(plausiblePhone("020 7946 0018")).toBe(true);
    expect(plausiblePhone("42")).toBe(false);
    expect(plausiblePhone("1111111111")).toBe(false);
  });

  it("knows a date", () => {
    expect(plausibleDate("1981-04-02")).toBe(true);
    expect(plausibleDate("2/4/1981")).toBe(true);
    expect(plausibleDate("19810402")).toBe(true);
    expect(plausibleDate("last Tuesday")).toBe(false);
  });
});

describe("hashes", () => {
  it("knows the shapes of a digest and a stored hash", () => {
    expect(looksLikeHash("5f4dcc3b5aa765d61d8327deb882cf99")).toBe(true);
    expect(looksLikeHash("$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")).toBe(true);
    expect(looksLikeHash("{SSHA}bWlrZXNhbHQxMjM0NTY3ODkwMTIzNA==")).toBe(true);
    expect(looksLikeHash("pbkdf2_sha256$600000$abc$def")).toBe(true);
    expect(looksLikeHash("hunter2")).toBe(false);
  });
});

describe("decoding", () => {
  it("undoes form encoding", () => {
    expect(decodeForm("ann%40corp.test")).toBe("ann@corp.test");
    expect(decodeForm("a+b")).toBe("a b");
    expect(decodeForm("100%")).toBe("100%"); // a bad escape is left alone
  });

  it("decodes base64 text and refuses bytes", () => {
    expect(decodeBase64(btoa("admin:letmein"))).toBe("admin:letmein");
    expect(decodeBase64("TlRMTVNTUAABAAAAB4IIAA")).toBeNull();
    expect(decodeBase64("not base64 at all!!")).toBeNull();
  });

  it("counts digits", () => {
    expect(digits("4111-1111 1111.1111")).toBe("4111111111111111");
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
