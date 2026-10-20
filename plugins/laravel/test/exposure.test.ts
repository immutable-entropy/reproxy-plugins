import { describe, expect, it } from "reproxy/testing";
import { exposureFor } from "../src/exposure";

/** A single-page app answers 200 with its own shell, whatever the route. */
const spaShell = `<!DOCTYPE html><html><head><title>Shop</title></head><body><div id="app"></div>
<script type="module" src="/build/assets/index-4f1a.js"></script></body></html>`;

function id(path: string, body: string, contentType = "text/html"): string {
  const e = exposureFor(path, contentType, body);
  return e ? e.id : "";
}

describe("exposureFor", () => {
  it("knows a served .env, and lists the variables by name", () => {
    const env = "APP_NAME=Shop\nAPP_ENV=production\nAPP_KEY=base64:abcd\nDB_PASSWORD=secret\n";
    const e = exposureFor("/.env", "text/plain", env)!;
    expect(e.id).toBe("env_file");
    expect(e.fields!.variables).toBe("4");
    expect(e.fields!.names).toContain("DB_PASSWORD");
  });

  it("knows one in a subdirectory, and a named one", () => {
    expect(id("/app/.env", "APP_KEY=base64:abcd\n", "text/plain")).toBe("env_file");
    expect(id("/.env.production", "APP_ENV=production\n", "text/plain")).toBe("env_file");
  });

  it("leaves a page that merely sits at /.env alone", () => {
    expect(id("/.env", spaShell)).toBe("");
  });

  it("knows the application log", () => {
    const log = "[2026-10-19 09:14:02] production.ERROR: Call to a member function id() on null {\"exception\":\"...\"}\n";
    expect(id("/storage/logs/laravel.log", log, "text/plain")).toBe("storage_logs");
  });

  it("knows private storage, but leaves the public disk alone", () => {
    expect(id("/storage/app/invoices/9.pdf", "", "application/pdf")).toBe("storage_private");
    expect(id("/storage/framework/sessions/abc", "a:1:{}", "text/plain")).toBe("storage_private");
    expect(id("/storage/app/public/avatars/1.png", "", "image/png")).toBe("");
    expect(id("/storage/avatars/1.png", "", "image/png")).toBe("");
  });

  it("knows Telescope and Horizon by what they serve, not by their path", () => {
    const telescope = `<html><head><link href="/vendor/telescope/app.css"></head><body><div id="telescope"></div></body></html>`;
    const horizon = `<html><body><script>window.Horizon = {"path":"horizon"}</script></body></html>`;
    expect(id("/telescope/requests", telescope)).toBe("telescope");
    expect(id("/horizon/dashboard", horizon)).toBe("horizon");
    expect(id("/telescope", spaShell)).toBe("");
    expect(id("/horizon", spaShell)).toBe("");
  });

  it("knows Ignition's health check, and whether it can run commands", () => {
    const e = exposureFor("/_ignition/health-check", "application/json", '{"can_execute_commands":true}')!;
    expect(e.id).toBe("ignition");
    expect(e.fields!.can_execute_commands).toBe("true");
    expect(e.extra).toContain("live");
    expect(e.note + e.fix).toContain("CVE-2021-3129");
  });

  it("knows the Debugbar's routes", () => {
    expect(id("/_debugbar/open?id=X", '{"__meta":{"id":"X"}}', "application/json")).toBe("debugbar");
  });

  it("reads the framework version out of an exposed composer.lock", () => {
    const lock = `{"packages":[{"name":"laravel/framework","version":"v10.48.4","source":{}}]}`;
    const e = exposureFor("/composer.lock", "application/json", lock)!;
    expect(e.id).toBe("composer_file");
    expect(e.fields!.laravel_framework).toBe("v10.48.4");
  });

  it("reads the constraint out of an exposed composer.json", () => {
    const json = `{"require":{"php":"^8.1","laravel/framework":"^10.10"}}`;
    expect(exposureFor("/composer.json", "application/json", json)!.fields!.laravel_framework).toBe("^10.10");
  });

  it("knows a project file served above public/", () => {
    expect(id("/vendor/composer/installed.json", "{}", "application/json")).toBe("project_file");
    expect(id("/artisan", "#!/usr/bin/env php", "text/plain")).toBe("project_file");
  });

  it("says nothing about an ordinary path", () => {
    expect(id("/api/orders", '{"data":[]}', "application/json")).toBe("");
  });
});
