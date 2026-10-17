import { describe, expect, it } from "reproxy/testing";
import { detectFrameworks, frameworkForDep, frameworkForExt, label, versioned } from "../src/frameworks";

describe("detectFrameworks", () => {
  it("puts a meta-framework before the base it implies", () => {
    const d = detectFrameworks(`<div id="__next"></div><script src="/_next/x.js"></script>`);
    expect(d.map((x) => x.id)).toEqual(["next", "react"]);
    expect(d[1].signals[0]).toContain("implied by Next.js");
  });

  it("returns nothing for a page with no markers", () => {
    expect(detectFrameworks("<h1>plain</h1>")).toEqual([]);
  });
});

describe("frameworkForDep", () => {
  it("maps a dependency package to its framework (a meta's base library)", () => {
    expect(frameworkForDep("react-dom")).toBe("react");
    expect(frameworkForDep("@vue/runtime-core")).toBe("vue");
    expect(frameworkForDep("vue-router")).toBe("vue");
    expect(frameworkForDep("nuxt")).toBe("vue"); // Nuxt's base is Vue
    expect(frameworkForDep("next")).toBe("react");
    expect(frameworkForDep("@sveltejs/kit")).toBe("svelte");
    expect(frameworkForDep("@angular/core")).toBe("angular");
    expect(frameworkForDep("lodash")).toBeUndefined();
  });
});

describe("frameworkForExt", () => {
  it("maps an app source extension to its framework", () => {
    expect(frameworkForExt("src/App.vue")).toBe("vue");
    expect(frameworkForExt("src/Counter.svelte")).toBe("svelte");
    expect(frameworkForExt("src/main.ts")).toBeUndefined();
  });
});

describe("versioned", () => {
  it("reports frameworks, build tools and UI kits, not arbitrary packages", () => {
    expect(versioned("vue")).toBe(true);
    expect(versioned("react")).toBe(true);
    expect(versioned("vite")).toBe(true);
    expect(versioned("@mui/material")).toBe(true);
    expect(versioned("@angular/core")).toBe(true);
    expect(versioned("left-pad")).toBe(false);
  });
});

describe("label", () => {
  it("names a meta-framework with its base", () => {
    expect(label({ id: "nuxt", name: "Nuxt", base: "vue", signals: [] })).toBe("Nuxt (Vue.js)");
    expect(label({ id: "react", name: "React", signals: [] })).toBe("React");
  });
});
