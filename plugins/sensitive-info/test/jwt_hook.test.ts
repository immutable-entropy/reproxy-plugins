import { describe, it, expect, mock } from "reproxy/testing";

const jwt = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogIkFsaWNlIiwgImFkbWluIjogdHJ1ZSwgImV4cCI6IDE3MzU2ODk2MDAsICJyb2xlcyI6IFsiYSIsICJiIl0sICJjdHgiOiB7ImlwIjogIjEuMi4zLjQifX0.c2ln";

describe("JWT findings carry decoded claims", () => {
  it("says nothing about the bearer token the tester is carrying", async () => {
    await mock.dispatch("traffic.on_request_forwarded", {
      url: "https://app.test/api",
      method: "GET",
      requestHeaders: { Authorization: "Bearer " + jwt },
    });
    expect(mock.findings()).toHaveLength(0);
  });

  it("decodes one in a header when the policy is turned off", async () => {
    mock.settings({ header_session_tokens: true });
    await mock.dispatch("traffic.on_request_forwarded", {
      url: "https://app.test/api",
      method: "GET",
      requestHeaders: { Authorization: "Bearer " + jwt },
    });
    const f = mock.findings().find((x) => x.value === jwt)!;
    expect(f).toBeDefined();
    const fields: Record<string, string> = {};
    for (const kv of f.fields) fields[kv.key] = kv.value;
    expect(fields["jwt.sub"]).toBe("1234567890");
    expect(fields["jwt.admin"]).toBe("true");
    expect(fields["detector"]).toBe("jwt");
  });

  it("decodes a JWT found in a response body", async () => {
    await mock.dispatch("traffic.on_response_received", {
      url: "https://app.test/token",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: JSON.stringify({ access_token: jwt }),
    });
    const f = mock.findings().find((x) => x.value === jwt)!;
    const fields: Record<string, string> = {};
    for (const kv of f.fields) fields[kv.key] = kv.value;
    expect(fields["jwt.name"]).toBe("Alice");
  });
});
