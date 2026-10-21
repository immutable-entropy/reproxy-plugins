import { describe, expect, it } from "reproxy/testing";
import { fromCookie, fromHeaders, fromHtml, fromPath, verdict } from "../src/detect";
import { kindOf, parseSetCookie } from "../src/cookies";

const ENC = "eyJpdiI6IkZha2VJdkZvclRlc3RzPT0iLCJ2YWx1ZSI6ImZha2UifQ%3D%3D";

function cookieSignal(line: string) {
  const c = parseSetCookie([line])[0];
  return fromCookie(c, kindOf(c));
}
function html(s: string) {
  return fromHtml(s.toLowerCase());
}

describe("fromCookie", () => {
  it("takes an encrypted Laravel cookie as proof", () => {
    expect(cookieSignal(`laravel_session=${ENC}; path=/`)!.strong).toBe(true);
    expect(cookieSignal(`shop_session=${ENC}; path=/`)!.strong).toBe(true);
    expect(cookieSignal(`XSRF-TOKEN=${ENC}; path=/`)!.strong).toBe(true);
  });

  it("takes a bare XSRF-TOKEN as a hint only", () => {
    expect(cookieSignal("XSRF-TOKEN=abc123; path=/")!.strong).toBe(false);
  });

  it("says nothing about somebody else's cookie", () => {
    expect(cookieSignal("_ga=GA1.2.3; path=/")).toBeUndefined();
  });
});

describe("fromHtml and fromPath", () => {
  it("knows the framework's own path and Livewire", () => {
    expect(html('<pre>/srv/app/vendor/laravel/framework/src/Illuminate/Foundation/Application.php</pre>')[0].strong).toBe(true);
    expect(html('<script src="/livewire/livewire.js"></script>')[0].strong).toBe(true);
  });

  it("treats a csrf-token meta tag as a hint only", () => {
    const signals = html('<meta name="csrf-token" content="xyz">');
    expect(signals).toHaveLength(1);
    expect(signals[0].strong).toBe(false);
  });

  it("knows the routes Laravel's packages register", () => {
    expect(fromPath("/_ignition/health-check")[0].strong).toBe(true);
    expect(fromPath("/sanctum/csrf-cookie")[0].strong).toBe(true);
    expect(fromPath("/api/orders")).toEqual([]);
  });

  it("knows the Debugbar's header", () => {
    expect(fromHeaders([{ name: "phpdebugbar-id", value: "Xf9" }])[0].strong).toBe(true);
    expect(fromHeaders([{ name: "Content-Type", value: "text/html" }])).toEqual([]);
  });
});

describe("verdict", () => {
  it("needs one strong signal", () => {
    const v = verdict([{ why: "the laravel_session cookie", strong: true }]);
    expect(v.laravel).toBe(true);
    expect(v.certain).toBe(true);
  });

  it("or two weak ones, and says it is only probable", () => {
    const weak = (why: string) => ({ why, strong: false });
    expect(verdict([weak("a")]).laravel).toBe(false);
    const v = verdict([weak("a csrf-token tag"), weak("assets under /build/")]);
    expect(v.laravel).toBe(true);
    expect(v.certain).toBe(false);
    expect(v.why).toBe("a csrf-token tag; assets under /build/");
  });

  it("counts the same evidence once", () => {
    const weak = (why: string) => ({ why, strong: false });
    expect(verdict([weak("a"), weak("a")]).laravel).toBe(false);
  });
});
