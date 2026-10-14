import { describe, it, expect, mock } from "reproxy/testing";
import { sameSite } from "../main";

describe("mapResponse", () => {
  it("puts same-site URLs on the map when no targets are set", async () => {
    const flow = mock.flow({
      url: "https://www.app.test/",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: JSON.stringify({ api: "https://api.app.test/v1/users/42", ads: "https://tracker.other.test/pixel" }),
    });
    expect(await mock.dispatch("traffic.on_response_received", flow)).toBe(1);
    const mapped = mock.endpoints();
    expect(mapped.map((e) => e.url)).toEqual(["https://api.app.test/v1/users/{id}"]);
    expect(mapped[0].visited).toBe(false);
    expect(mapped[0].origin).toBe("plugin:endpoint-mapper");
    expect(mapped[0].links[0].fromFlowId).toBe(flow.id);
    expect(mapped[0].links[0].detail).toBe("json:$.api");
  });

  it("maps everything with include_out_of_scope", async () => {
    mock.settings({ include_out_of_scope: true });
    await mock.dispatch("traffic.on_response_received", {
      url: "https://www.app.test/",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: JSON.stringify({ ads: "https://tracker.other.test/pixel" }),
    });
    expect(mock.endpoints()).toHaveLength(1);
  });

  it("templates OpenAPI paths like the traffic's", async () => {
    await mock.dispatch("traffic.on_response_received", {
      url: "https://app.test/openapi.json",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: JSON.stringify({ openapi: "3.1.0", paths: { "/orders/{orderId}/items/{itemId}": { get: {} } } }),
    });
    expect(mock.endpoints().map((e) => e.url)).toContain("https://app.test/orders/{id}/items/{id2}");
  });

  it("is not called for error pages or images", async () => {
    expect(
      await mock.dispatch("traffic.on_response_received", {
        url: "https://app.test/missing",
        status: 404,
        responseHeaders: { "Content-Type": "text/html" },
        responseBody: `<a href="/x">x</a>`,
      }),
    ).toBe(0);
    expect(
      await mock.dispatch("traffic.on_response_received", {
        url: "https://app.test/i.png",
        responseHeaders: { "Content-Type": "image/png" },
        responseBody: "x",
      }),
    ).toBe(0);
  });
});

describe("sameSite", () => {
  it("compares the last two labels", () => {
    expect(sameSite("https://a.corp.test/x", "http://b.corp.test:8080/")).toBe(true);
    expect(sameSite("https://corp.test/", "https://other.test/")).toBe(false);
  });
});
