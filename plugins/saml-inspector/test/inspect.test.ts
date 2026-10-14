import { describe, it, expect } from "reproxy/testing";
import { inspect, attributes, tagContent, attr, firstTag } from "../src/inspect";

const opts = { flagAttributes: true, flagWeaknesses: true, maxAgeHours: 12, sensitive: ["ssn", "password", "creditcard"] };
const blob = { kind: "SAMLResponse" as const, binding: "post" as const, raw: "", where: "SAMLResponse form field" };

const signed = `
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@corp.test</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData Recipient="https://sp.example.com/acs" NotOnOrAfter="2024-01-01T00:05:00Z"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2024-01-01T00:05:00Z"/>
  <saml:AttributeStatement>
    <saml:Attribute Name="email"><saml:AttributeValue>alice@corp.test</saml:AttributeValue></saml:Attribute>
    <saml:Attribute Name="SSN"><saml:AttributeValue>123-45-6789</saml:AttributeValue></saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>`;

describe("xml helpers", () => {
  it("reads tags, attributes and attribute statements", () => {
    expect(tagContent(signed, "NameID")).toBe("alice@corp.test");
    expect(attr(firstTag(signed, "NameID")!, "Format")).toContain("emailAddress");
    const attrs = attributes(signed);
    expect(attrs.map((a) => a.name)).toEqual(["email", "SSN"]);
    expect(attrs[1].values).toEqual(["123-45-6789"]);
  });
});

describe("inspect", () => {
  it("surfaces the subject, attributes and no weaknesses on a sound assertion", () => {
    const got = inspect(signed, blob, opts);
    const byType = (t: string) => got.filter((c) => c.type === t);
    expect(byType("saml-subject")).toHaveLength(1);
    expect(byType("saml-subject")[0].value).toBe("alice@corp.test");
    expect(byType("saml-attribute")).toHaveLength(2);
    expect(got.find((c) => c.title === "Sensitive SAML attribute")!.value).toContain("SSN");
    expect(byType("saml-weakness")).toHaveLength(0);
  });

  it("flags an unsigned assertion, bearer without recipient, and a long window", () => {
    const weak = signed
      .replace(/<ds:Signature[\s\S]*?<\/ds:Signature>/, "")
      .replace(' Recipient="https://sp.example.com/acs"', "")
      .replace('NotOnOrAfter="2024-01-01T00:05:00Z"/>\n  <saml:AttributeStatement', 'NotOnOrAfter="2024-01-02T00:00:00Z"/>\n  <saml:AttributeStatement');
    const titles = inspect(weak, blob, opts).filter((c) => c.type === "saml-weakness").map((c) => c.title);
    expect(titles).toContain("Unsigned SAML assertion");
    expect(titles).toContain("Bearer subject without a Recipient");
    expect(titles).toContain("Long assertion validity window");
  });

  it("respects flag_attributes off (sensitive still flagged)", () => {
    const got = inspect(signed, blob, { ...opts, flagAttributes: false });
    const attrs = got.filter((c) => c.type === "saml-attribute");
    expect(attrs).toHaveLength(1);
    expect(attrs[0].value).toContain("SSN");
  });
});

describe("JWT in a SAML attribute", () => {
  const jwt = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkFsaWNlIiwgImFkbWluIjogdHJ1ZSwgImV4cCI6IDE3MzU2ODk2MDAsICJyb2xlcyI6IFsiYSIsICJiIl0sICJjdHgiOiB7ImlwIjogIjEuMi4zLjQifX0.c2ln";
  const withJwt = `
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>A</ds:SignatureValue></ds:Signature>
  <saml:AttributeStatement>
    <saml:Attribute Name="access_token"><saml:AttributeValue>${jwt}</saml:AttributeValue></saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>`;

  it("decodes the JWT into the attribute finding's fields", () => {
    const got = inspect(withJwt, blob, opts);
    const attr = got.find((c) => c.type === "saml-attribute")!;
    expect(attr).toBeDefined();
    expect(attr.detail).toContain("JWT");
    expect(attr.fields["jwt.sub"]).toBe("1234567890");
    expect(attr.fields["jwt.admin"]).toBe("true");
    expect(attr.fields["attribute"]).toBe("access_token");
  });
});
