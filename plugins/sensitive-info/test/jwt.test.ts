import { describe, it, expect } from "reproxy/testing";
import { decodeClaims } from "../src/jwt";

const jwt = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkFsaWNlIiwgImFkbWluIjogdHJ1ZSwgImV4cCI6IDE3MzU2ODk2MDAsICJyb2xlcyI6IFsiYSIsICJiIl0sICJjdHgiOiB7ImlwIjogIjEuMi4zLjQifX0.c2ln";

describe("decodeClaims", () => {
  it("flattens the payload into jwt.* fields", () => {
    const c = decodeClaims(jwt)!;
    expect(c["jwt.sub"]).toBe("1234567890");
    expect(c["jwt.name"]).toBe("Alice");
    expect(c["jwt.admin"]).toBe("true");
    expect(c["jwt.roles"]).toBe("a, b");
    expect(c["jwt.ctx.ip"]).toBe("1.2.3.4");
    expect(c["jwt.header.alg"]).toBe("HS256");
  });

  it("spells out time claims", () => {
    expect(decodeClaims(jwt)!["jwt.exp"]).toContain("2025-01-01");
  });

  it("rejects non-JWTs", () => {
    expect(decodeClaims("not.a.jwt")).toBeNull();
    expect(decodeClaims("onlyonepart")).toBeNull();
  });
});
