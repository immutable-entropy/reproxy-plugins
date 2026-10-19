import { describe, expect, it } from "reproxy/testing";
import { keys, mergeNotes } from "../src/ssl/notes";

describe("mergeNotes", () => {
  it("keeps what an earlier lookup saw that this one didn't", () => {
    const old = {
      [keys.certificates]: "5",
      [keys.issuers]: "Example CA (R1)",
      [keys.firstIssued]: "2025-01-01",
      [keys.latestExpiry]: "2027-01-01",
      [keys.sources]: "crt.sh",
    };
    const fresh = {
      [keys.certificates]: "3",
      [keys.issuers]: "Other CA, Example CA (R1)",
      [keys.firstIssued]: "2026-01-01",
      [keys.latestExpiry]: "2026-06-01",
      [keys.sources]: "ctlogs.dev",
      [keys.wildcards]: "",
    };
    const got = mergeNotes(old, fresh);
    expect(got[keys.certificates]).toBe("5");
    expect(got[keys.issuers]).toBe("Other CA, Example CA (R1)");
    expect(got[keys.firstIssued]).toBe("2025-01-01");
    expect(got[keys.latestExpiry]).toBe("2027-01-01");
    expect(got[keys.sources]).toBe("crt.sh, ctlogs.dev");
    expect(got[keys.wildcards]).toBe("");
  });
});
