import { describe, it, expect, mock } from "reproxy/testing";

describe("scanResponse", () => {
  it("records a finding linked to the flow", async () => {
    const flow = mock.flow({
      url: "https://app.test/api/config",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: `{"stripe": "sk_live_4eC39HqLyjWDarjtT1zdp7dc"}`,
    });
    expect(await mock.dispatch("traffic.on_response_received", flow)).toBe(1);
    const found = mock.findings();
    expect(found).toHaveLength(1);
    expect(found[0].value).toBe("sk_live_4eC39HqLyjWDarjtT1zdp7dc");
    expect(found[0].types).toEqual(["secret-key"]);
    expect(found[0].source).toBe("plugin");
    expect(found[0].links[0].flowId).toBe(flow.id);
    expect(found[0].links[0].location).toBe("response_body");
  });

  it("is not called for images", async () => {
    const flow = mock.flow({
      url: "https://app.test/logo.png",
      responseHeaders: { "Content-Type": "image/png" },
      responseBody: "AKIAIOSFODNN7EXAMPLE",
    });
    expect(await mock.dispatch("traffic.on_response_received", flow)).toBe(0);
    expect(mock.findings()).toHaveLength(0);
  });

  it("merges a secret seen twice into one finding", async () => {
    for (let i = 0; i < 2; i++) {
      await mock.dispatch("traffic.on_response_received", {
        url: `https://app.test/page/${i}`,
        responseHeaders: { "Content-Type": "text/html" },
        responseBody: "<!-- AKIAIOSFODNN7EXAMPLE -->",
      });
    }
    const found = mock.findings();
    expect(found).toHaveLength(1);
    expect(found[0].links).toHaveLength(2);
  });

  it("records a leaked password hash from a JSON API", async () => {
    await mock.dispatch("traffic.on_response_received", {
      url: "https://app.test/api/users/1",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: `{"id":1,"email":"ann@corp.test","password_hash":"$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}`,
    });
    const types = mock.findings().map((f) => f.types[0]).sort();
    expect(types).toEqual(["hash", "personal-data"]);
  });
});

describe("scanRequest", () => {
  it("records the credentials of a login", async () => {
    await mock.dispatch("traffic.on_request_forwarded", {
      url: "https://app.test/login",
      method: "POST",
      requestHeaders: { "Content-Type": "application/x-www-form-urlencoded" },
      requestBody: "user=ann&pass=hunter2",
    });
    const values = mock.findings().map((f) => f.value).sort();
    expect(values).toEqual(["ann", "hunter2"]);
    expect(mock.findings()[0].links[0].location).toBe("request_body");
  });

  it("records a credential in the URL's query string, and says why that is worse", async () => {
    await mock.dispatch("traffic.on_request_forwarded", {
      url: "https://app.test/reset?email=ann%40corp.test&token=8f2kq9d1x7bqw3zt5r6y",
      method: "GET",
    });
    const f = mock.findings().find((x) => x.value === "8f2kq9d1x7bqw3zt5r6y")!;
    expect(f).toBeDefined();
    expect(f.links[0].location).toBe("request_header");
    expect(f.notes).toContain("Referer");
  });

  it("records the Basic credentials of a request, decoded", async () => {
    await mock.dispatch("traffic.on_request_forwarded", {
      url: "https://app.test/admin",
      requestHeaders: { Authorization: "Basic " + btoa("admin:letmein") },
    });
    const f = mock.findings()[0];
    expect(f.value).toBe("admin:letmein");
    expect(f.links[0].location).toBe("request_header");
  });

  it("can be switched off", async () => {
    mock.settings({ scan_requests: false });
    await mock.dispatch("traffic.on_request_forwarded", {
      url: "https://app.test/login",
      method: "POST",
      requestBody: "password=hunter2",
    });
    expect(mock.findings()).toHaveLength(0);
  });

  it("stops at the findings cap", async () => {
    mock.settings({ max_findings: 2 });
    await mock.dispatch("traffic.on_request_forwarded", {
      url: "https://app.test/import",
      method: "POST",
      requestHeaders: { "Content-Type": "text/plain" },
      requestBody: "a@corp.test b@corp.test c@corp.test d@corp.test e@corp.test",
    });
    expect(mock.findings()).toHaveLength(2);
  });
});

describe("hiding secret values", () => {
  it("records a secret hidden and personal data in the clear", async () => {
    await mock.dispatch("traffic.on_response_received", {
      url: "https://app.test/api/me",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: `{"email":"ann@corp.test","api_key":"Zx9Qm2Lw7Vb4Np8Kr3Ty","ssn":"234-56-7890"}`,
    });
    const hidden: Record<string, boolean> = {};
    for (const f of mock.findings()) hidden[f.value] = f.hidden;
    expect(hidden["Zx9Qm2Lw7Vb4Np8Kr3Ty"]).toBe(true);
    expect(hidden["234-56-7890"]).toBe(true);
    expect(hidden["ann@corp.test"]).toBe(false);
  });

  it("can be switched off", async () => {
    mock.settings({ hide_secrets: false });
    await mock.dispatch("traffic.on_response_received", {
      url: "https://app.test/api/me",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: `{"api_key":"Zx9Qm2Lw7Vb4Np8Kr3Ty"}`,
    });
    expect(mock.findings()[0].hidden).toBe(false);
  });
});

describe("scanWebSocket", () => {
  it("records a credential sent over a socket, from either side", async () => {
    const flow = mock.flow({
      url: "https://app.test/socket",
      status: 101,
      wsMessages: [
        { direction: "sent", text: `{"type":"login","user":"ann","password":"hunter2"}` },
        { direction: "received", text: `{"type":"ok","session":"8f2kq9d1x7bqw3zt5r6y"}` },
      ],
    });
    expect(await mock.dispatch("websocket.on_message", flow)).toBe(2);
    const found = mock.findings();
    const values = found.map((f) => f.value).sort();
    expect(values).toEqual(["8f2kq9d1x7bqw3zt5r6y", "ann", "hunter2"]);
    const session = found.find((f) => f.value === "8f2kq9d1x7bqw3zt5r6y")!;
    expect(session.links[0].location).toBe("response_body");
    expect(session.notes).toContain("WebSocket message 2");
    expect(session.hidden).toBe(true);
  });

  it("leaves a binary message alone", async () => {
    const flow = mock.flow({
      url: "https://app.test/socket",
      status: 101,
      wsMessages: [{ direction: "sent", type: "binary", text: "password=hunter2" }],
    });
    expect(await mock.dispatch("websocket.on_message", flow)).toBe(1);
    expect(mock.findings()).toHaveLength(0);
  });
});
