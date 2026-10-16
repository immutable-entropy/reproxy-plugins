import { describe, expect, it } from "reproxy/testing";
import { pemBody, sanDNSNames } from "../src/der";
import { testPEM } from "./fixture";

describe("sanDNSNames", () => {
  it("reads a certificate's DNS names, and only those", () => {
    const der = pemBody("some text before\n" + testPEM + "\nand after");
    expect(der).toBeDefined();
    expect(sanDNSNames(der!)).toEqual(["www.example.test", "example.test", "shop.other-brand.test"]);
  });

  it("gives nothing rather than wrong names for what isn't a certificate", () => {
    expect(pemBody("<html>502 Bad Gateway</html>")).toBeUndefined();
    expect(sanDNSNames(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]))).toBeUndefined();
    // Cut off half-way through the SAN extension.
    const der = pemBody(testPEM)!;
    const at = [...der].findIndex((b, i) => b === 0x55 && der[i + 1] === 0x1d && der[i + 2] === 0x11);
    expect(sanDNSNames(der.slice(0, at + 12))).toBeUndefined();
  });
});
