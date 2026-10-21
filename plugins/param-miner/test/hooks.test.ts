import { beforeEach, describe, expect, it, mock } from "reproxy/testing";
import { mine, setPace, setRunToken } from "../main";
import { candidatesFor } from "../src/candidates";
import { canaryValue } from "../src/detect";

// A deterministic run token so a scripted response can echo a known canary.
const RUN = "zztest";

beforeEach(() => {
  setRunToken(RUN);
  setPace(0);
});

/** The canary value the plugin will give a name when mining query. */
function canaryFor(name: string, existing: string[] = ["q"]): string {
  const names = candidatesFor("query", [], existing);
  return canaryValue(RUN, names.indexOf(name));
}

const flow = { url: "https://app.test/search?q=hello", method: "GET", requestHeaders: { Cookie: "sid=abc" } };

/** Everything that isn't scripted gets a steady 200, so the baseline is stable. */
function steady() {
  mock.respond(".*", { status: 200, headers: { "Content-Type": "text/html" }, body: "<html>results</html>" });
}

function names(): string[] {
  return mock.findings().map((f) => f.fields.find((x) => x.key === "name")!.value);
}

describe("behavioural discovery", () => {
  it("finds a query parameter that changes the status, and records it once", async () => {
    mock.settings({ locations: ["query"] });
    // "admin" flips the response to 403; everything else is steady.
    mock.respond("[?&]admin=", { status: 403, headers: { "Content-Type": "text/html" }, body: "<html>denied</html>" });
    steady();

    const { ran, message } = await mock.action("mine", flow);
    expect(ran).toBe(true);
    expect(names()).toEqual(["admin"]);
    const f = mock.findings()[0];
    expect(f.value).toBe("admin (query parameter, app.test)");
    expect(f.fields.find((x) => x.key === "detection")!.value).toBe("status");
    expect(f.types).toEqual(["hidden-param"]);
    expect(message).toContain("admin");
  });

  it("confirms nothing on a target that reacts to no guess", async () => {
    mock.settings({ locations: ["query"] });
    steady();
    const { message } = await mock.action("mine", flow);
    expect(mock.findings()).toHaveLength(0);
    expect(message).toContain("no hidden parameters confirmed");
  });
});

describe("reflection discovery", () => {
  it("finds a query parameter whose value is reflected", async () => {
    mock.settings({ locations: ["query"] });
    // The "debug" probe's response echoes debug's canary value.
    mock.respond("[?&]debug=", { status: 200, headers: { "Content-Type": "text/html" }, body: `<p>${canaryFor("debug")}</p>` });
    steady();

    await mock.action("mine", flow);
    expect(names()).toEqual(["debug"]);
    const f = mock.findings()[0];
    expect(f.fields.find((x) => x.key === "detection")!.value).toBe("reflected");
    expect(f.notes).toContain("reflected");
  });
});

describe("a target that reacts to any unknown input", () => {
  it("stops reporting behavioural guesses, and says so", async () => {
    mock.settings({ locations: ["query"] });
    // The control probe (junk names carry the run's zz marker) trips a 500,
    // so behavioural detection is switched off for this location.
    mock.respond(`${RUN}zz`, { status: 500, headers: { "Content-Type": "text/html" }, body: "err" });
    // A parameter that only changes the status must now be ignored: without
    // the fallback it would be reported against a target that answers
    // differently to anything it doesn't recognise.
    mock.respond("[?&]admin=", { status: 403, headers: { "Content-Type": "text/html" }, body: "denied" });
    steady();

    const { message } = await mock.action("mine", flow);
    expect(names()).not.toContain("admin");
    expect(mock.findings()).toHaveLength(0);
    expect(message).toContain("only reflected names are reported");
  });
});

describe("headers", () => {
  it("finds a reflected request header (the CDN/unkeyed-input case)", async () => {
    mock.settings({ locations: ["header"] });
    // When mining headers, the header name isn't in the URL, so match on the
    // cache-buster (every probe has one) and echo a fixed marker that the
    // header candidate will carry.
    // Instead: a header probe that reflects is scripted by matching the
    // run's cache-buster and returning a body with X-Original-URL's canary.
    const value = canaryValue(RUN, candidatesFor("header", [], Object.keys({ Cookie: 1, Host: 1 })).indexOf("X-Original-URL"));
    mock.respond(`cb_${RUN}=`, { status: 200, headers: { "Content-Type": "text/html" }, body: `<p>${value}</p>` });

    await mock.action("mine", flow);
    // Every header probe's response now contains that one canary, so only
    // X-Original-URL is reported (its value is the one echoed).
    expect(names()).toEqual(["X-Original-URL"]);
    const f = mock.findings()[0];
    expect(f.value).toContain("header");
    expect(f.notes).toContain("unkeyed input");
  });
});

describe("the request budget", () => {
  it("stops at the cap and says so", async () => {
    mock.settings({ locations: ["query"], max_requests: 10 });
    steady();
    const { message } = await mock.action("mine", flow);
    expect(mock.sent().length).toBeLessThan(11);
    expect(message).toContain("request cap");
  });

  it("sends nothing but the action when there is nothing to answer", async () => {
    mock.settings({ locations: ["query"] });
    // No steady() rule: the harness answers 0; baseline can't be read.
    const { message } = await mock.action("mine", { url: "https://app.test/x", method: "GET" });
    expect(message).toContain("Param Miner");
  });
});
