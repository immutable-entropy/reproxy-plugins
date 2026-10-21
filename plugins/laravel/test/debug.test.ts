import { describe, expect, it } from "reproxy/testing";
import { appKeyIn, readHtmlError, readJsonError } from "../src/debug";

/** Ignition's page, cut down: the title, and the context JSON it embeds. */
const ignition = `<!DOCTYPE html><html><head><meta name="robots" content="noindex, nofollow">
<title>SQLSTATE[42S02]: Base table or view not found: 1146 Table 'shop.orders' doesn't exist</title></head>
<body><div id="app"></div><script>window.data = {"report":{"exception_class":"Illuminate\\\\Database\\\\QueryException",
"context":{"env":{"laravel_version":"10.48.4","php_version":"8.2.12","laravel_locale":"en","app_debug":true,"app_env":"production"}},
"frames":[{"file":"\\/srv\\/shop\\/vendor\\/laravel\\/framework\\/src\\/Illuminate\\/Database\\/Connection.php","line_number":760}]}};
</script><script src="/_ignition/scripts/ignition.js"></script></body></html>`;

/** Whoops' page, cut down to its banner and its server-data table. */
const whoops = `<!DOCTYPE html><html><head><title>Call to a member function format() on null</title></head>
<body><div class="Whoops container"><h1>Whoops, looks like something went wrong.</h1>
<span class="frame-file">/var/www/billing/app/Http/Controllers/InvoiceController.php</span>
<span class="frame-file">/var/www/billing/vendor/laravel/framework/src/Illuminate/Routing/Controller.php</span>
<h2>Environment &amp; details:</h2><table><tbody>
<tr><td>APP_ENV</td><td>production</td></tr>
<tr><td>APP_DEBUG</td><td>true</td></tr>
<tr><td>APP_KEY</td><td>base64:fFfR8Kq2nM7xV1pLw0aZbQ4tY6uI9oP3sD5gH8jK2lM=</td></tr>
<tr><td>DB_HOST</td><td>10.0.0.9</td></tr>
<tr><td>DB_USERNAME</td><td>billing</td></tr>
<tr><td>DB_PASSWORD</td><td>n0t-a-real-one</td></tr>
<tr><td>MAIL_PASSWORD</td><td>n0t-a-real-one-either</td></tr>
</tbody></table></div></body></html>`;

function read(html: string) {
  return readHtmlError(html, html.toLowerCase());
}

describe("readHtmlError", () => {
  it("reads Ignition's page", () => {
    const e = read(ignition)!;
    expect(e.kind).toBe("ignition");
    expect(e.laravel).toBe(true);
    expect(e.laravelVersion).toBe("10.48.4");
    expect(e.phpVersion).toBe("8.2.12");
    expect(e.appEnv).toBe("production");
    expect(e.root).toBe("/srv/shop");
    expect(e.message).toContain("Base table or view not found");
    expect(e.appKey).toBe("");
    expect(e.envNames).toEqual([]);
  });

  it("reads Whoops' page, and the environment it prints", () => {
    const e = read(whoops)!;
    expect(e.kind).toBe("whoops");
    expect(e.laravel).toBe(true);
    expect(e.root).toBe("/var/www/billing");
    expect(e.message).toBe("Call to a member function format() on null");
    expect(e.appKey).toBe("base64:fFfR8Kq2nM7xV1pLw0aZbQ4tY6uI9oP3sD5gH8jK2lM=");
    expect(e.envNames).toContain("DB_PASSWORD");
    expect(e.envNames).toContain("MAIL_PASSWORD");
  });

  it("says nothing about an ordinary page", () => {
    expect(read("<html><body><h1>Page not found</h1><p>Sorry.</p></body></html>")).toBeUndefined();
  });

  it("says nothing about a page that only mentions an exception", () => {
    expect(read("<html><body><p>An exception was raised at the board meeting.</p></body></html>")).toBeUndefined();
  });

  it("needs more than a passing mention before it calls it an environment table", () => {
    const page = `<html><head><title>Boom</title></head><body><h1>Whoops, looks like something went wrong.</h1>
<p>Check that APP_ENV is set correctly.</p></body></html>`;
    const e = read(page)!;
    expect(e.kind).toBe("whoops");
    expect(e.envNames).toEqual([]);
  });
});

describe("readJsonError", () => {
  const trace = [{ file: "/srv/shop/app/Http/Controllers/OrderController.php", line: 31, function: "show" }];

  it("reads the reply debug mode adds", () => {
    const e = readJsonError({
      message: "No query results for model [App\\Models\\Order] 9",
      exception: "Illuminate\\Database\\Eloquent\\ModelNotFoundException",
      file: "/srv/shop/vendor/laravel/framework/src/Illuminate/Database/Eloquent/Builder.php",
      line: 625,
      trace,
    })!;
    expect(e.kind).toBe("json");
    expect(e.laravel).toBe(true);
    expect(e.line).toBe("625");
    expect(e.root).toBe("/srv/shop");
    expect(e.evidence).toContain("1-frame");
  });

  it("says nothing about the reply with debug off", () => {
    expect(readJsonError({ message: "Server Error" })).toBeUndefined();
    expect(readJsonError({ message: "The route api/x could not be found." })).toBeUndefined();
  });

  it("says nothing about ordinary JSON", () => {
    expect(readJsonError({ data: [1, 2, 3] })).toBeUndefined();
    expect(readJsonError([1, 2, 3])).toBeUndefined();
    expect(readJsonError(undefined)).toBeUndefined();
  });

  it("holds back on the framework when the exception isn't Laravel's", () => {
    const e = readJsonError({
      message: "boom",
      exception: "RuntimeException",
      file: "/app/src/Service.php",
      line: 10,
      trace: [],
    })!;
    expect(e.laravel).toBe(false);
  });
});

describe("appKeyIn", () => {
  it("reads a key out of an .env file", () => {
    const env = "APP_NAME=Shop\nAPP_ENV=production\nAPP_KEY=base64:aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/abcd=\nAPP_DEBUG=false\n";
    expect(appKeyIn(env)).toBe("base64:aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/abcd=");
  });

  it("finds nothing when there is nothing", () => {
    expect(appKeyIn("APP_KEY=\nAPP_ENV=production\n")).toBe("");
  });
});
