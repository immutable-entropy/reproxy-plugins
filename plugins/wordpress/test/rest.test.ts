import { describe, it, expect } from "reproxy/testing";
import { readRest, routeOf } from "../src/rest";

describe("routeOf", () => {
  it("reads the route out of a /wp-json path", () => {
    expect(routeOf("/wp-json/", "")).toBe("/");
    expect(routeOf("/wp-json", "")).toBe("/");
    expect(routeOf("/wp-json/wp/v2/users", "")).toBe("/wp/v2/users");
  });

  it("reads the route out of a rest_route query", () => {
    expect(routeOf("/", "rest_route=%2Fwp%2Fv2%2Fusers")).toBe("/wp/v2/users");
    expect(routeOf("/index.php", "rest_route=/")).toBe("/");
  });

  it("is empty for a request that isn't the REST API's", () => {
    expect(routeOf("/wp-admin/admin-ajax.php", "action=x")).toBe("");
  });
});

describe("readRest", () => {
  it("takes the namespaces core doesn't register from the root", () => {
    const facts = readRest("/", {
      name: "Blog",
      namespaces: ["oembed/1.0", "wp/v2", "wp-site-health/v1", "wp-abilities/v1", "woocommerce/v3", "yoast/v1"],
    });
    expect(facts.map((f) => f.name)).toEqual(["woocommerce", "yoast"]);
    expect(facts[0].kind).toBe("rest-namespace");
    expect(facts[0].evidence).toContain("woocommerce/v3");
  });

  // wptavern.com's root lists six jetpack namespaces among twenty-one.
  it("groups one plugin's namespaces together", () => {
    const facts = readRest("/", {
      namespaces: ["jetpack/v4", "jetpack/v4/blaze", "jetpack/v4/stats-app", "jetpack/v4/import", "jetpack/v4/explat", "akismet/v1"],
    });
    expect(facts.map((f) => f.name)).toEqual(["jetpack", "akismet"]);
    expect(facts[0].evidence).toContain("…");
  });

  it("reads the accounts the users route lists", () => {
    const facts = readRest("/wp/v2/users", [
      { id: 1, name: "Jane Doe", slug: "jane" },
      { id: 4, name: "editor", slug: "editor" },
    ]);
    expect(facts.map((f) => f.name)).toEqual(["jane", "editor"]);
    expect(facts[0].kind).toBe("user");
    expect(facts[0].evidence).toContain("as user 1");
    expect(facts[0].evidence).toContain("Jane Doe");
  });

  it("reads an oEmbed reply's author", () => {
    const facts = readRest("/oembed/1.0/embed", { author_name: "jane", author_url: "https://blog.test/author/jane/" });
    expect(facts).toHaveLength(1);
    expect(facts[0].kind).toBe("user");
    expect(facts[0].name).toBe("jane");
  });

  it("reads the inventory when wp/v2/plugins answers", () => {
    const facts = readRest("/wp/v2/plugins", [
      { plugin: "akismet/akismet", status: "active", name: "Akismet Anti-spam", version: "5.3.1" },
      { plugin: "hello", status: "inactive", name: "Hello Dolly", version: "1.7.2" },
    ]);
    expect(facts.map((f) => f.kind)).toEqual(["plugin", "plugin"]);
    expect(facts[0].name).toBe("akismet");
    expect(facts[0].version).toBe("5.3.1");
    expect(facts[1].name).toBe("hello");
  });

  it("reads wp/v2/themes", () => {
    const facts = readRest("/wp/v2/themes", [{ stylesheet: "twentytwentyfour", version: "1.2" }]);
    expect(facts[0].kind).toBe("theme");
    expect(facts[0].name).toBe("twentytwentyfour");
    expect(facts[0].version).toBe("1.2");
  });

  it("leaves a reply that isn't what its route suggests alone", () => {
    expect(readRest("/wp/v2/users", { code: "rest_user_cannot_view", message: "Sorry" })).toHaveLength(0);
    expect(readRest("/wp/v2/posts", [{ id: 1, slug: "hello-world", title: { rendered: "Hello" } }])).toHaveLength(0);
    expect(readRest("", { namespaces: ["woocommerce/v3"] })).toHaveLength(0);
    expect(readRest("/", null)).toHaveLength(0);
    expect(readRest("/", "not json")).toHaveLength(0);
  });
});
