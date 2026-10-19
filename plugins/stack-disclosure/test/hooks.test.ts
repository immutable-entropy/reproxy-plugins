import { beforeEach, describe, expect, it, mock } from "reproxy/testing";
import { load, scanResponse } from "../main";

beforeEach(() => load());

/** The detector ids a response's findings tripped. */
function detectors(): string[] {
  return mock.findings().map((f) => f.fields.find((x) => x.key === "detector")?.value ?? "");
}

describe("scanResponse", () => {
  it("records a disclosure readable, never hidden", async () => {
    const flow = mock.flow({
      url: "https://app.test/",
      responseHeaders: { "Content-Type": "text/html", "X-Powered-By": "PHP/7.4.3" },
      responseBody: "<p>hi</p>",
    });
    expect(await mock.dispatch("traffic.on_response_received", flow)).toBe(1);
    const [f] = mock.findings();
    expect(f.types).toEqual(["disclosure"]);
    expect(f.value).toBe("X-Powered-By: PHP/7.4.3");
    expect(f.hidden).toBe(false);
    expect(f.links[0].location).toBe("response_header");
  });

  it("records a disclosure once per host, with notes that merge", async () => {
    const response = (url: string) => ({
      url,
      responseHeaders: { "Content-Type": "text/html", Server: "Apache/2.4.41 (Ubuntu)" },
      responseBody: "<p>hello</p>",
    });
    await mock.dispatch("traffic.on_response_received", response("https://app.test/a"));
    await mock.dispatch("traffic.on_response_received", response("https://app.test/b"));
    await mock.dispatch("traffic.on_response_received", response("https://api.app.test/c"));
    const found = mock.findings();
    expect(found).toHaveLength(1);
    expect(found[0].value).toBe("Server: Apache/2.4.41 (Ubuntu)");
    expect(found[0].links.map((l) => l.url)).toEqual(["https://app.test/a", "https://api.app.test/c"]);
    expect(found[0].notes.split("Web server banner")).toHaveLength(2); // written once
    expect(found[0].notes).toContain("ServerTokens Prod");
  });

  it("drops bare banners when only versions are wanted", async () => {
    mock.settings({ versions_only: true });
    await mock.dispatch("traffic.on_response_received", {
      url: "https://app.test/",
      responseHeaders: { Server: "nginx", "X-Powered-By": "PHP/8.1.2", "X-Backend-Server": "web-03" },
    });
    expect(detectors()).toEqual(["tech_header", "internal_host"]);
  });

  it("skips a detector by id", async () => {
    mock.settings({ skip_detectors: ["server_banner"] });
    await mock.dispatch("traffic.on_response_received", {
      url: "https://app.test/",
      responseHeaders: { Server: "Apache/2.4.41", "X-Backend-Server": "web-03" },
    });
    expect(detectors()).toEqual(["internal_host"]);
  });
});
