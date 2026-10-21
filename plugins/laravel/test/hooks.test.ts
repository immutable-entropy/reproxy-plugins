import { beforeEach, describe, expect, it, mock } from "reproxy/testing";
import { targets } from "reproxy";
import { idle, load, setRequestGap } from "../main";

beforeEach(async () => {
  load();
  setRequestGap(0);
  await idle();
});

const ENC = "eyJpdiI6IkZha2VJdkZvclRlc3RzPT0iLCJ2YWx1ZSI6ImZha2UifQ%3D%3D";

/** A fixture whose targetId is set when a target covers it, as core does. */
function flow(partial: Record<string, unknown>): Record<string, unknown> {
  const t = targets.list().find((x) => x.value === "app.test");
  const url = String(partial.url);
  return { targetId: t && url.indexOf("https://app.test/") === 0 ? t.id : "", ...partial };
}

/** The response that puts a Laravel app on the map: its session cookies. */
function laravelFlow(url = "https://app.test/", attrs = "; path=/; secure; httponly; samesite=lax") {
  return flow({
    url,
    responseHeaders: { "Content-Type": "text/html", "Set-Cookie": `laravel_session=${ENC}${attrs}` },
    responseBody: "<html><body>Shop</body></html>",
  });
}

function values(type: string): string[] {
  return mock
    .findings()
    .filter((f) => f.types.indexOf(type) >= 0)
    .map((f) => f.value);
}

const dispatch = (f: unknown) => mock.dispatch("traffic.on_response_received", f as never);

describe("recognising the app", () => {
  it("records Laravel from its session cookie, with the evidence", async () => {
    // Two targets accept an in-scope 200 of HTML: the head check and the
    // body check. The exposure check's paths turn it away.
    expect(await dispatch(laravelFlow())).toBe(2);
    const [f] = mock.findings();
    expect(f.value).toBe("Laravel (app.test)");
    expect(f.types).toEqual(["laravel"]);
    expect(f.notes).toContain("the laravel_session cookie");
    expect(f.hidden).toBe(false);
  });

  it("waits for a second hint when no single one is conclusive", async () => {
    const page = (body: string) =>
      flow({ url: "https://app.test/", responseHeaders: { "Content-Type": "text/html" }, responseBody: body });
    await dispatch(page('<html><head><meta name="csrf-token" content="x"></head></html>'));
    expect(mock.findings()).toHaveLength(0);
    await dispatch(page('<html><body><script src="/build/assets/app-1.js"></script></body></html>'));
    expect(values("laravel")).toEqual(["Laravel (app.test)"]);
    expect(mock.findings()[0].notes).toContain("probable rather than certain");
  });

  it("says nothing about a host that isn't Laravel", async () => {
    await dispatch(
      flow({
        url: "https://app.test/",
        responseHeaders: { "Content-Type": "text/html", "Set-Cookie": "_ga=GA1.2.3; path=/" },
        responseBody: "<html><body>hello</body></html>",
      }),
    );
    expect(mock.findings()).toHaveLength(0);
  });

  it("is kept out of traffic no target covers", async () => {
    mock.target("domain", "app.test");
    expect(await dispatch(laravelFlow("https://other.test/"))).toBe(0);
    expect(mock.findings()).toHaveLength(0);
  });
});

describe("session cookies", () => {
  it("flags the attributes a session cookie is missing", async () => {
    await dispatch(laravelFlow("https://app.test/", "; path=/"));
    expect(values("laravel-config").sort()).toEqual([
      "laravel_session without HttpOnly (app.test)",
      "laravel_session without SameSite (app.test)",
      "laravel_session without Secure (app.test)",
    ]);
    const f = mock.findings().find((x) => x.value.indexOf("HttpOnly") > 0)!;
    expect(f.notes).toContain("SESSION_HTTP_ONLY");
    expect(f.links[0].location).toBe("response_header");
  });

  it("says nothing about a cookie that is set properly", async () => {
    await dispatch(laravelFlow());
    expect(values("laravel-config")).toEqual([]);
  });

  it("leaves the cookies alone when asked to", async () => {
    mock.settings({ check_cookies: false });
    await dispatch(laravelFlow("https://app.test/", "; path=/"));
    expect(values("laravel-config")).toEqual([]);
    expect(values("laravel")).toHaveLength(1);
  });

  it("records one finding per cookie per host, however many responses set it", async () => {
    await dispatch(laravelFlow("https://app.test/a", "; path=/; httponly; samesite=lax"));
    await dispatch(laravelFlow("https://app.test/b", "; path=/; httponly; samesite=lax"));
    // The same cookie on the same host is one finding, linked to the first
    // response that showed it: every later response would say the same.
    expect(values("laravel-config")).toEqual(["laravel_session without Secure (app.test)"]);
    const f = mock.findings().find((x) => x.types.indexOf("laravel-config") >= 0)!;
    expect(f.links).toHaveLength(1);
    expect(f.links[0].url).toBe("https://app.test/a");
  });

  it("but reports each host it sees the cookie on", async () => {
    await dispatch(laravelFlow("https://app.test/a", "; path=/; httponly; samesite=lax"));
    await dispatch(laravelFlow("https://api.app.test/b", "; path=/; httponly; samesite=lax"));
    expect(values("laravel-config").sort()).toEqual([
      "laravel_session without Secure (api.app.test)",
      "laravel_session without Secure (app.test)",
    ]);
  });
});

describe("debug mode", () => {
  const trace = [{ file: "/srv/shop/app/Http/Controllers/OrderController.php", line: 31 }];
  const jsonError = JSON.stringify({
    message: "No query results for model [App\\Models\\Order] 9",
    exception: "Illuminate\\Database\\Eloquent\\ModelNotFoundException",
    file: "/srv/shop/vendor/laravel/framework/src/Illuminate/Database/Eloquent/Builder.php",
    line: 625,
    trace,
  });

  it("flags the JSON reply debug mode adds, and the version it names", async () => {
    await dispatch(laravelFlow());
    expect(
      await dispatch(
        flow({
          url: "https://app.test/api/orders/9",
          status: 500,
          responseHeaders: { "Content-Type": "application/json" },
          responseBody: jsonError,
        }),
      ),
    ).toBe(2);
    expect(values("laravel-debug")).toEqual(["Debug mode on (app.test)"]);
    const f = mock.findings().find((x) => x.types.indexOf("laravel-debug") >= 0)!;
    expect(f.notes).toContain("APP_DEBUG=false");
    expect(f.notes).toContain("/srv/shop");
    expect(f.links[0].location).toBe("response_body");
  });

  it("says nothing about the reply with debug off", async () => {
    await dispatch(laravelFlow());
    await dispatch(
      flow({
        url: "https://app.test/api/orders/9",
        status: 500,
        responseHeaders: { "Content-Type": "application/json" },
        responseBody: '{"message":"Server Error"}',
      }),
    );
    expect(values("laravel-debug")).toEqual([]);
  });

  it("records the APP_KEY a Whoops page prints, hidden, and the environment with it", async () => {
    const page = `<html><head><title>Boom</title></head><body><h1>Whoops, looks like something went wrong.</h1>
      <span>/var/www/billing/vendor/laravel/framework/src/Illuminate/Routing/Controller.php</span>
      <table><tr><td>APP_KEY</td><td>base64:fFfR8Kq2nM7xV1pLw0aZbQ4tY6uI9oP3sD5gH8jK2lM=</td></tr>
      <tr><td>DB_PASSWORD</td><td>n0t-a-real-one</td></tr><tr><td>DB_USERNAME</td><td>billing</td></tr></table></body></html>`;
    await dispatch(
      flow({
        url: "https://app.test/invoices/1",
        status: 500,
        responseHeaders: { "Content-Type": "text/html" },
        responseBody: page,
      }),
    );
    expect(values("laravel")).toEqual(["Laravel (app.test)"]);
    expect(values("laravel-debug").sort()).toEqual([
      "Debug mode on (app.test)",
      "Server environment in an error page (app.test)",
    ]);
    const key = mock.findings().find((f) => f.types.indexOf("laravel-secret") >= 0)!;
    expect(key.value).toBe("base64:fFfR8Kq2nM7xV1pLw0aZbQ4tY6uI9oP3sD5gH8jK2lM=");
    expect(key.hidden).toBe(true);
    expect(key.notes).toContain("key:generate");
  });

  it("keeps the key out of the findings when asked to", async () => {
    mock.settings({ record_app_key: false });
    await dispatch(
      flow({
        url: "https://app.test/x",
        status: 500,
        responseHeaders: { "Content-Type": "text/html" },
        responseBody: `<h1>Whoops, looks like something went wrong.</h1><p>/srv/app/vendor/laravel/framework/x.php</p>
          <td>APP_KEY</td><td>base64:fFfR8Kq2nM7xV1pLw0aZbQ4tY6uI9oP3sD5gH8jK2lM=</td>`,
      }),
    );
    expect(values("laravel-secret")).toEqual([]);
    expect(values("laravel-debug")).toEqual(["Debug mode on (app.test)"]);
  });

  it("never reads a body the filters turn away", async () => {
    await dispatch(laravelFlow());
    // An image: only the head check accepts it.
    expect(
      await dispatch(flow({ url: "https://app.test/logo.png", responseHeaders: { "Content-Type": "image/png" }, responseBody: "..." })),
    ).toBe(1);
  });
});

describe("exposed paths", () => {
  it("records Telescope, and takes it as proof of Laravel", async () => {
    const dashboard = `<html><head><link href="/vendor/telescope/app.css"></head><body></body></html>`;
    expect(
      await dispatch(
        flow({ url: "https://app.test/telescope/requests", responseHeaders: { "Content-Type": "text/html" }, responseBody: dashboard }),
      ),
    ).toBe(3);
    expect(values("laravel-exposure")).toEqual(["Telescope is reachable (app.test)"]);
    expect(values("laravel")).toEqual(["Laravel (app.test)"]);
  });

  it("holds its tongue when the path is a single-page app's route", async () => {
    await dispatch(laravelFlow());
    await dispatch(
      flow({
        url: "https://app.test/telescope",
        responseHeaders: { "Content-Type": "text/html" },
        responseBody: `<html><body><div id="app"></div></body></html>`,
      }),
    );
    expect(values("laravel-exposure")).toEqual([]);
  });

  it("records a served .env and the key in it", async () => {
    await dispatch(
      flow({
        url: "https://app.test/.env",
        responseHeaders: { "Content-Type": "text/plain" },
        responseBody: "APP_ENV=production\nAPP_KEY=base64:aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/abcd=\nDB_PASSWORD=x\n",
      }),
    );
    expect(values("laravel-exposure")).toEqual(["The .env file is served (app.test)"]);
    expect(values("laravel-secret")).toEqual(["base64:aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/abcd="]);
    const f = mock.findings().find((x) => x.types.indexOf("laravel-exposure") >= 0)!;
    expect(f.fields.find((x) => x.key === "names")!.value).toContain("DB_PASSWORD");
  });
});

describe("the active check", () => {
  beforeEach(() => {
    mock.target("domain", "app.test");
    mock.settings({ active_probe: true, probe_paths: [".env", "telescope"] });
  });

  it("asks each path once per origin, and records what comes back", async () => {
    mock.respond("/\\.env$", { status: 200, headers: { "Content-Type": "text/plain" }, body: "APP_ENV=production\nAPP_KEY=base64:zz\nDB_PASSWORD=x\n" });
    mock.respond("/telescope$", { status: 404, headers: { "Content-Type": "text/html" }, body: "<h1>Not Found</h1>" });

    await dispatch(laravelFlow());
    await idle();
    await dispatch(laravelFlow("https://app.test/second"));
    await idle();

    expect(mock.sent().map((s) => s.url)).toEqual(["https://app.test/.env", "https://app.test/telescope"]);
    expect(values("laravel-exposure")).toEqual(["The .env file is served (app.test)"]);
  });

  it("takes a host it already knew when the setting is turned on later", async () => {
    mock.settings({ active_probe: false });
    await dispatch(laravelFlow());
    await idle();
    expect(mock.sent()).toHaveLength(0);

    mock.settings({ active_probe: true, probe_paths: [".env"] });
    await dispatch(laravelFlow("https://app.test/next"));
    await idle();
    expect(mock.sent().map((s) => s.url)).toEqual(["https://app.test/.env"]);
  });

  it("stays quiet unless the user turns it on", async () => {
    mock.settings({ active_probe: false });
    await dispatch(laravelFlow());
    await idle();
    expect(mock.sent()).toHaveLength(0);
  });

  it("never asks a host twice, even after the plugin is reloaded", async () => {
    mock.respond("/\\.env$", { status: 404, headers: { "Content-Type": "text/html" }, body: "<h1>Not Found</h1>" });
    mock.respond("/telescope$", { status: 404, headers: { "Content-Type": "text/html" }, body: "<h1>Not Found</h1>" });

    await dispatch(laravelFlow());
    await idle();
    expect(mock.sent()).toHaveLength(2);

    // A reload clears the session's state; the engagement's record of what
    // was checked is what has to stop the second round.
    load();
    setRequestGap(0);
    await dispatch(laravelFlow("https://app.test/again"));
    await idle();
    expect(mock.sent()).toHaveLength(2);
  });

  it("does not work a checked host out a second time, but keeps watching it", async () => {
    mock.respond("/\\.env$", { status: 404, headers: { "Content-Type": "text/html" }, body: "<h1>Not Found</h1>" });
    mock.respond("/telescope$", { status: 404, headers: { "Content-Type": "text/html" }, body: "<h1>Not Found</h1>" });
    await dispatch(laravelFlow());
    await idle();
    expect(values("laravel")).toEqual(["Laravel (app.test)"]);

    load();
    setRequestGap(0);
    // The site is not recorded again — one sighting, not two …
    await dispatch(laravelFlow("https://app.test/again", "; path=/"));
    await idle();
    expect(mock.findings().find((f) => f.types.indexOf("laravel") >= 0)!.links).toHaveLength(1);
    // … and the passive checks still run against it.
    expect(values("laravel-config")).toContain("laravel_session without Secure (app.test)");
  });

  it("writes what it checked onto the origin in the Explorer", async () => {
    const fixture = laravelFlow();
    mock.entity(fixture as never, "host");
    mock.respond("/\\.env$", {
      status: 200,
      headers: { "Content-Type": "text/plain" },
      body: "APP_ENV=production\nAPP_KEY=base64:zz\nDB_PASSWORD=x\n",
    });
    mock.respond("/telescope$", { status: 404, headers: { "Content-Type": "text/html" }, body: "<h1>Not Found</h1>" });

    await dispatch(fixture);
    await idle();

    const origin = mock.entities().find((e) => e.key === "https://app.test")!;
    expect(origin.kv["laravel"]).toContain("the laravel_session cookie");
    expect(origin.kv["laravel-checked"]).toContain("2 paths asked");
    expect(origin.kv["laravel-checked"]).toContain("env_file");
    // The kv note is written only after the engagement record is, and it
    // carries the same asked/found that record holds, so it is proof the
    // record was written. That the record then stops a re-probe is the
    // "never asks a host twice" test's job, not this one's.
  });

  it("asks nothing when the list of paths is empty", async () => {
    mock.settings({ active_probe: true, probe_paths: [] });
    await dispatch(laravelFlow());
    await idle();
    expect(mock.sent()).toHaveLength(0);
  });

  it("reads a debug page that comes back from a path that isn't there", async () => {
    mock.respond("/\\.env$", { status: 404, headers: { "Content-Type": "text/html" }, body: "<h1>Not Found</h1>" });
    mock.respond("/telescope$", {
      status: 500,
      headers: { "Content-Type": "text/html" },
      body: `<html><title>Boom</title><body><h1>Whoops, looks like something went wrong.</h1>
        <p>/srv/shop/vendor/laravel/framework/src/Illuminate/Routing/Router.php</p></body></html>`,
    });
    await dispatch(laravelFlow());
    await idle();
    expect(values("laravel-debug")).toEqual(["Debug mode on (app.test)"]);
  });
});
