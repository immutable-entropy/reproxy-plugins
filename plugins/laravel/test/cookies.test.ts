import { describe, expect, it } from "reproxy/testing";
import { encrypted, issues, kindOf, parseSetCookie, setCookies, type Cookie } from "../src/cookies";

/** A value shaped like one of Laravel's encrypted cookies. */
const ENC = "eyJpdiI6IkZha2VJdkZvclRlc3RzPT0iLCJ2YWx1ZSI6ImZha2UiLCJtYWMiOiJmYWtlIn0%3D";

function cookie(line: string): Cookie {
  return parseSetCookie([line])[0];
}
function ids(c: Cookie, https = true): string[] {
  return issues(c, kindOf(c), https).map((i) => i.id);
}

describe("parseSetCookie", () => {
  it("reads the name, the value and the attributes", () => {
    const c = cookie(`laravel_session=${ENC}; expires=Tue, 20 Oct 2026 12:00:00 GMT; Max-Age=7200; path=/; secure; httponly; samesite=lax`);
    expect(c.name).toBe("laravel_session");
    expect(c.value).toBe(ENC);
    expect(c.secure).toBe(true);
    expect(c.httpOnly).toBe(true);
    expect(c.sameSite).toBe("lax");
    expect(c.maxAge).toBe("7200");
  });

  it("takes each Set-Cookie line, and skips what isn't one", () => {
    const headers = [
      { name: "Content-Type", value: "text/html" },
      { name: "Set-Cookie", value: "XSRF-TOKEN=abc; path=/" },
      { name: "set-cookie", value: "laravel_session=def; path=/" },
      { name: "Set-Cookie", value: "broken" },
    ];
    expect(setCookies(headers)).toHaveLength(3);
    expect(parseSetCookie(setCookies(headers)).map((c) => c.name)).toEqual(["XSRF-TOKEN", "laravel_session"]);
  });
});

describe("kindOf", () => {
  it("knows Laravel's encrypted payload", () => {
    expect(encrypted(ENC)).toBe(true);
    expect(encrypted("abc123")).toBe(false);
  });

  it("names the session, remember-me and CSRF cookies", () => {
    expect(kindOf(cookie(`laravel_session=${ENC}`))).toBe("session");
    expect(kindOf(cookie(`myapp_session=${ENC}`))).toBe("session");
    expect(kindOf(cookie(`remember_web_59ba36addc2b2f9401580f014c7f58ea4e30989d=${ENC}`))).toBe("remember");
    expect(kindOf(cookie(`XSRF-TOKEN=${ENC}`))).toBe("csrf");
  });

  it("calls any other encrypted cookie encrypted, and leaves the rest alone", () => {
    expect(kindOf(cookie(`theme=${ENC}`))).toBe("encrypted");
    expect(kindOf(cookie("_ga=GA1.2.3"))).toBe("");
  });
});

describe("issues", () => {
  it("passes a properly set session cookie", () => {
    expect(ids(cookie(`laravel_session=${ENC}; path=/; secure; httponly; samesite=lax`))).toEqual([]);
  });

  it("flags a session cookie with nothing set", () => {
    expect(ids(cookie(`laravel_session=${ENC}; path=/`))).toEqual(["no_secure", "no_httponly", "no_samesite"]);
  });

  it("says nothing about Secure on a page served over http", () => {
    expect(ids(cookie(`laravel_session=${ENC}; path=/; httponly; samesite=lax`), false)).toEqual([]);
  });

  it("leaves XSRF-TOKEN its readability, which is the design", () => {
    expect(ids(cookie(`XSRF-TOKEN=${ENC}; path=/; secure; samesite=lax`))).toEqual([]);
    expect(ids(cookie(`XSRF-TOKEN=${ENC}; path=/; samesite=lax`))).toEqual(["no_secure"]);
  });

  it("flags SameSite=None without Secure once, as the thing browsers reject", () => {
    expect(ids(cookie(`laravel_session=${ENC}; path=/; httponly; samesite=none`))).toEqual([
      "no_secure",
      "samesite_none_insecure",
    ]);
  });

  it("flags a cross-site session cookie that is otherwise set correctly", () => {
    expect(ids(cookie(`laravel_session=${ENC}; path=/; secure; httponly; samesite=none`))).toEqual(["samesite_none"]);
  });

  it("flags a session cookie the app excluded from encryption", () => {
    expect(ids(cookie("laravel_session=eyJhIjoxfQ; path=/; secure; httponly; samesite=lax"))).toEqual(["not_encrypted"]);
  });

  it("asks only for Secure on another encrypted cookie", () => {
    expect(ids(cookie(`theme=${ENC}; path=/`))).toEqual(["no_secure"]);
  });

  it("says nothing about a cookie that isn't Laravel's", () => {
    expect(ids(cookie("_ga=GA1.2.3; path=/"))).toEqual([]);
  });
});
