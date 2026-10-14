import { describe, it, expect, mock } from "reproxy/testing";

function b64(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion><saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>bob@corp.test</saml:NameID></saml:Subject>
    <saml:AttributeStatement><saml:Attribute Name="password"><saml:AttributeValue>hunter2</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion></samlp:Response>`;

describe("scanResponse", () => {
  it("records findings for a SAML POST response", async () => {
    const html = `<form action="https://sp.example.com/acs" method="post"><input type="hidden" name="SAMLResponse" value="${b64(response)}"/></form>`;
    const n = await mock.dispatch("traffic.on_response_received", {
      url: "https://idp.example.com/sso",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: html,
    });
    expect(n).toBe(1);
    const types = mock.findings().map((f) => f.types[0]).sort();
    expect(types).toContain("saml-subject");
    expect(types).toContain("saml-weakness"); // unsigned
    const pw = mock.findings().find((f) => f.value.indexOf("password") >= 0);
    expect(pw!.types).toContain("saml-attribute");
    expect(mock.findings()[0].links[0].location).toBe("response_body");
  });

  it("ignores pages with no SAML", async () => {
    await mock.dispatch("traffic.on_response_received", {
      url: "https://app.test/",
      responseHeaders: { "Content-Type": "text/html" },
      responseBody: "<html>hello</html>",
    });
    expect(mock.findings()).toHaveLength(0);
  });
});

describe("scanRequest", () => {
  it("decodes a SAMLResponse posted back to the SP", async () => {
    await mock.dispatch("traffic.on_request_forwarded", {
      url: "https://sp.example.com/acs",
      method: "POST",
      requestHeaders: { "Content-Type": "application/x-www-form-urlencoded" },
      requestBody: "SAMLResponse=" + encodeURIComponent(b64(response)) + "&RelayState=/home",
    });
    expect(mock.findings().length).toBeGreaterThan(0);
    expect(mock.findings()[0].links[0].location).toBe("request_body");
  });
});
