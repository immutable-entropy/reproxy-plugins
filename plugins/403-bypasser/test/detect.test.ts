import { describe, expect, it } from "reproxy/testing";
import { blockedBaselineOf, isBlocked, reacted, servesContent, signalOf, type Signal } from "../src/detect";

const blocked = [401, 403];
const j = { blocked, includeRedirects: false };

/** A blocked baseline: three identical 403s with a short body. */
function block(body = "<html>denied</html>"): ReturnType<typeof blockedBaselineOf> {
  const s = signalOf(403, body.length, body);
  return blockedBaselineOf([s, s, s]);
}

describe("status predicates", () => {
  it("knows the blocked statuses", () => {
    expect(isBlocked(403, blocked)).toBe(true);
    expect(isBlocked(200, blocked)).toBe(false);
  });
  it("counts 2xx as content, and 3xx only when allowed", () => {
    expect(servesContent(200, false)).toBe(true);
    expect(servesContent(204, false)).toBe(true);
    expect(servesContent(302, false)).toBe(false);
    expect(servesContent(302, true)).toBe(true);
    expect(servesContent(404, true)).toBe(false);
  });
});

describe("blockedBaselineOf", () => {
  it("reduces agreeing samples to their status and length", () => {
    const bl = block();
    expect(bl.status).toBe(403);
    expect(bl.hasBody).toBe(true);
    expect(bl.lengthStable).toBe(true);
  });
  it("marks a status the samples disagree on as -1", () => {
    const bl = blockedBaselineOf([signalOf(403, 10, "a"), signalOf(401, 10, "a")]);
    expect(bl.status).toBe(-1);
  });
});

describe("reacted", () => {
  const bl = block();

  it("reports a 200 whose body differs from the block page", () => {
    expect(reacted(bl, signalOf(200, 40, "<html>the secret admin area</html>"), j)).toBe("body");
  });
  it("reports a 200 whose length is well outside the block page's", () => {
    const big = "x".repeat(5000);
    expect(reacted(bl, signalOf(200, big.length, big), j)).toBe("length");
  });
  it("says nothing when the variant is still blocked", () => {
    expect(reacted(bl, signalOf(403, 18, "<html>denied</html>"), j)).toBe("");
  });
  it("says nothing for a status that doesn't serve content (404)", () => {
    expect(reacted(bl, signalOf(404, 30, "<html>not found here</html>"), j)).toBe("");
  });
  it("says nothing when a 200 is the same block page", () => {
    // Some apps answer 'access denied' with a 200; that is not a bypass.
    expect(reacted(bl, signalOf(200, 18, "<html>denied</html>"), j)).toBe("");
  });
  it("judges a bodyless response (HEAD) by its status leaving the block", () => {
    expect(reacted(bl, signalOf(200, 0, ""), j)).toBe("status");
  });

  it("ignores a 3xx by default but takes one when redirects are allowed", () => {
    const empty = signalOf(302, 0, "");
    expect(reacted(bl, empty, j)).toBe("");
    expect(reacted(bl, empty, { blocked, includeRedirects: true })).toBe("status");
  });

  it("for an override, rejects a response that merely echoes the base path", () => {
    const control: Signal = signalOf(200, 24, "<html>the home page</html>");
    const sameAsControl = signalOf(200, 24, "<html>the home page</html>");
    const protectedContent = signalOf(200, 30, "<html>the admin console</html>");
    expect(reacted(bl, sameAsControl, { blocked, includeRedirects: false, control })).toBe("");
    expect(reacted(bl, protectedContent, { blocked, includeRedirects: false, control })).toBe("body");
  });
});
