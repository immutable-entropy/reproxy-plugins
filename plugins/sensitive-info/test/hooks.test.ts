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

  it("can be switched off", async () => {
    mock.settings({ scan_requests: false });
    await mock.dispatch("traffic.on_request_forwarded", {
      url: "https://app.test/login",
      method: "POST",
      requestBody: "password=hunter2",
    });
    expect(mock.findings()).toHaveLength(0);
  });
});
