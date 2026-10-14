import { describe, it, expect } from "reproxy/testing";
import { findSamlBlobs, decodeSaml, fromBase64 } from "../src/decode";

const assertionXML =
  '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' +
  "<saml:Assertion><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion></samlp:Response>";

function b64(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// A real raw-DEFLATE + base64 SAMLRequest (the Redirect binding), of a small
// AuthnRequest from https://sp.example.com.
const deflatedRequest =
  "fI+xagQxDER/xag/r9ekEmfDQZqFpElCijTBLIJbsGXHkuE+P+A0l+ZAjZhh3sxZUskNL0Ov/EY/g0TNrWQWnEKA0RlrkkOQUyFB3fH98vqC3jpsvWrdawazPQf4XsF8UpejcgBvHZhNZNDGook1gHf+6eTWk1s/nMN5XxBnAZzOfkd+DE4i1PWoDPGq2gSXRZqlWyotk91rOS93sfHv+78y/gYAAP//";

describe("finding blobs", () => {
  it("finds a POST SAMLResponse form field at the start of a body", () => {
    const body = "SAMLResponse=" + encodeURIComponent(b64(assertionXML)) + "&RelayState=x";
    const blobs = findSamlBlobs("https://sp.example.com/acs", body);
    const r = blobs.find((b) => b.kind === "SAMLResponse");
    expect(r!.binding).toBe("post");
    expect(decodeSaml(r!)).toContain("idp.example.com");
  });

  it("finds a redirect SAMLRequest query parameter", () => {
    const blobs = findSamlBlobs("https://idp.example.com/sso?SAMLRequest=abc123&RelayState=y", "");
    expect(blobs[0].kind).toBe("SAMLRequest");
    expect(blobs[0].binding).toBe("redirect");
  });

  it("finds a hidden input in an HTML form", () => {
    const html = '<form><input type="hidden" name="SAMLResponse" value="' + b64(assertionXML) + '"/></form>';
    const blobs = findSamlBlobs("https://sp.example.com/acs", html);
    expect(blobs.some((b) => b.kind === "SAMLResponse")).toBe(true);
  });

  it("finds raw XML", () => {
    const blobs = findSamlBlobs("https://sp/soap", "<soap><saml:Assertion/></soap>");
    expect(blobs.some((b) => b.kind === "xml")).toBe(true);
  });
});

describe("decoding", () => {
  it("decodes a POST blob", () => {
    const blob = { kind: "SAMLResponse" as const, binding: "post" as const, raw: b64(assertionXML), where: "x" };
    expect(decodeSaml(blob)).toContain("idp.example.com");
  });

  it("decodes a real DEFLATE redirect blob", () => {
    const blob = { kind: "SAMLRequest" as const, binding: "redirect" as const, raw: deflatedRequest, where: "x" };
    const xml = decodeSaml(blob);
    expect(xml).toContain("AuthnRequest");
    expect(xml).toContain("sp.example.com");
  });

  it("handles url-safe base64", () => {
    expect(fromBase64("YWJj")).not.toBeNull();
  });
});
