import { beforeEach, describe, expect, it, mock } from "reproxy/testing";
import { bypass, setPace, setRunToken } from "../main";

// A deterministic run token, and no pacing, so the probes are predictable.
const RUN = "zztest";
beforeEach(() => {
  setRunToken(RUN);
  setPace(0);
});

const flow = { url: "https://app.test/admin", method: "GET", requestHeaders: { Cookie: "sid=abc" } };

/** Everything not scripted first gets a 403 block page, so the baseline is blocked. */
function blocked() {
  mock.respond(".*", { status: 403, headers: { "Content-Type": "text/html" }, body: "<html>denied</html>" });
}

function raws(): string[] {
  return mock.sent().map((s) => s.raw);
}

describe("baseline", () => {
  it("does nothing when the chosen URL isn't blocked", async () => {
    mock.respond(".*", { status: 200, headers: { "Content-Type": "text/html" }, body: "<html>home</html>" });
    const { ran, message } = await mock.action("bypass", flow);
    expect(ran).toBe(true);
    expect(mock.findings()).toHaveLength(0);
    expect(message).toContain("nothing to bypass");
    expect(message).toContain("200");
  });
});

describe("a path bypass", () => {
  it("records one confirmed finding and confirms it with a second request", async () => {
    mock.settings({ techniques: ["path"] });
    // Only the "/admin/..;/" variant gets through, with different content.
    mock.respond("admin/\\.\\.;/", { status: 200, headers: { "Content-Type": "text/html" }, body: "<html>the secret admin area</html>" });
    blocked();

    const { ran, message } = await mock.action("bypass", flow);
    expect(ran).toBe(true);

    const f = mock.findings();
    expect(f).toHaveLength(1);
    expect(f[0].value).toContain("app.test/admin via path");
    expect(f[0].types).toEqual(["bypass"]);
    expect(f[0].fields.find((x) => x.key === "technique")!.value).toBe("path");
    expect(f[0].fields.find((x) => x.key === "result")!.value).toBe("200");
    expect(message).toContain("1 bypass confirmed");

    // Candidate + confirmation: the winning URL was sent at least twice.
    const wins = mock.sent().filter((s) => /admin\/\.\.;\//.test(s.url));
    expect(wins.length).toBeGreaterThan(1);
  });

  it("records nothing when every variant stays blocked", async () => {
    mock.settings({ techniques: ["path"] });
    blocked();
    const { message } = await mock.action("bypass", flow);
    expect(mock.findings()).toHaveLength(0);
    expect(message).toContain("no bypass found");
  });
});

describe("the other techniques are sent correctly", () => {
  it("injects headers, swaps the method, carries the override header, and downgrades to HTTP/1.0", async () => {
    blocked(); // nothing bypasses; we're checking what goes out
    await mock.action("bypass", flow);

    const sent = raws();
    expect(sent.some((r) => r.indexOf("X-Forwarded-For: 127.0.0.1") >= 0)).toBe(true);
    expect(sent.some((r) => r.indexOf("X-Original-URL: /admin") >= 0)).toBe(true);
    expect(sent.some((r) => r.indexOf(" HTTP/1.0") >= 0)).toBe(true);
    expect(mock.sent().some((s) => s.method === "POST")).toBe(true);
    // Every probe keeps the tester's own session.
    expect(sent.every((r) => r.indexOf("Cookie: sid=abc") >= 0)).toBe(true);
  });

  it("only runs the techniques that are turned on", async () => {
    mock.settings({ techniques: ["downgrade"] });
    blocked();
    await mock.action("bypass", flow);

    const sent = raws();
    // baseline (3) + the single downgrade = 4, and nothing else.
    expect(mock.sent()).toHaveLength(4);
    expect(sent.some((r) => r.indexOf(" HTTP/1.0") >= 0)).toBe(true);
    expect(sent.some((r) => r.indexOf("X-Forwarded-For") >= 0)).toBe(false);
    expect(mock.sent().some((s) => s.method === "POST")).toBe(false);
  });
});

describe("the request cap", () => {
  it("stops at the cap and says so", async () => {
    mock.settings({ max_requests: 8 });
    blocked();
    const { message } = await mock.action("bypass", flow);
    expect(mock.sent().length).toBeLessThan(9);
    expect(message).toContain("request cap");
  });
});
