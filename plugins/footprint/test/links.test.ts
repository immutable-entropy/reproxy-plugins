import { describe, expect, it } from "reproxy/testing";
import { classify } from "../src/links";

/** "type/detector/kind=value" for a URL, or null. */
function c(url: string): string | null {
  const h = classify(url);
  return h ? `${h.type}/${h.detector}/${h.kind ?? "-"}=${h.value}` : null;
}

describe("social media", () => {
  it("reads a profile from a platform host", () => {
    expect(c("https://twitter.com/acmeinc")).toBe("social-account/twitter/profile=https://twitter.com/acmeinc");
    expect(c("https://x.com/acmeinc")).toBe("social-account/twitter/profile=https://x.com/acmeinc");
    expect(c("https://www.facebook.com/AcmeInc")).toBe("social-account/facebook/profile=https://www.facebook.com/AcmeInc");
    expect(c("https://www.linkedin.com/company/acme")).toBe("social-account/linkedin/profile=https://www.linkedin.com/company/acme");
    expect(c("https://www.youtube.com/@acme")).toBe("social-account/youtube/profile=https://www.youtube.com/@acme");
  });

  it("tells a content link from a profile", () => {
    expect(c("https://twitter.com/acmeinc/status/123")).toBe("social-account/twitter/content=https://twitter.com/acmeinc/status/123");
    expect(c("https://youtu.be/dQw4w9WgXcQ")).toBe("social-account/youtube/content=https://youtu.be/dQw4w9WgXcQ");
    expect(c("https://www.youtube.com/watch?v=dQw4w9WgXcQ")?.startsWith("social-account/youtube/content=")).toBe(true);
  });

  it("ignores the platform's own share and intent links", () => {
    expect(c("https://twitter.com/intent/tweet?url=x")).toBeNull();
    expect(c("https://www.facebook.com/sharer/sharer.php?u=x")).toBeNull();
    expect(c("https://www.linkedin.com/sharing/share-offsite/?url=x")).toBeNull();
    expect(c("https://twitter.com/")).toBeNull();
  });
});

describe("source code", () => {
  it("reads an account and a repository", () => {
    expect(c("https://github.com/acme")).toBe("source-repo/github/profile=https://github.com/acme");
    expect(c("https://github.com/acme/widget")).toBe("source-repo/github/profile=https://github.com/acme/widget");
    expect(c("https://gitlab.com/acme/widget")).toBe("source-repo/gitlab/profile=https://gitlab.com/acme/widget");
    expect(c("https://codeberg.org/acme/widget")).toBe("source-repo/codeberg/profile=https://codeberg.org/acme/widget");
  });

  it("calls a file deep in a repository content, and knows GitHub's own pages", () => {
    expect(c("https://github.com/acme/widget/blob/main/README.md")).toBe("source-repo/github/content=https://github.com/acme/widget");
    expect(c("https://github.com/features/actions")).toBeNull();
    expect(c("https://github.com/login")).toBeNull();
  });

  it("labels a repository and an account differently", () => {
    expect(classify("https://github.com/acme")?.label).toBe("GitHub account");
    expect(classify("https://github.com/acme/widget")?.label).toBe("GitHub repository");
  });
});

describe("cloud storage", () => {
  it("reads a bucket from its host or path", () => {
    expect(c("https://my-bucket.s3.amazonaws.com/key.txt")).toBe("cloud-storage/bucket/-=my-bucket");
    expect(c("https://my-bucket.s3.eu-west-1.amazonaws.com/key")).toBe("cloud-storage/bucket/-=my-bucket");
    expect(c("https://s3.eu-west-1.amazonaws.com/other-bucket/key")).toBe("cloud-storage/bucket/-=other-bucket");
    expect(c("https://storage.googleapis.com/data-bkt/file")).toBe("cloud-storage/bucket/-=data-bkt");
    expect(c("https://acct.blob.core.windows.net/container/blob")).toBe("cloud-storage/bucket/-=acct/container");
  });
});

describe("package registries", () => {
  it("reads a package and its registry", () => {
    expect(c("https://www.npmjs.com/package/left-pad")).toBe("package/npm/-=npm:left-pad");
    expect(c("https://www.npmjs.com/package/@acme/widget")).toBe("package/npm/-=npm:@acme/widget");
    expect(c("https://pypi.org/project/requests/")).toBe("package/pypi/-=PyPI:requests");
    expect(c("https://packagist.org/packages/acme/lib")).toBe("package/packagist/-=Packagist:acme/lib");
    expect(c("https://ghcr.io/acme/app")).toBe("package/ghcr/-=ghcr.io/acme/app");
  });
});

describe("api and docs", () => {
  it("reads API and documentation endpoints on any host", () => {
    expect(c("https://api.acme.test/graphql")).toBe("api-endpoint/graphql/-=https://api.acme.test/graphql");
    expect(c("https://acme.test/v2/api-docs")).toBe("api-endpoint/openapi/-=https://acme.test/v2/api-docs");
    expect(c("https://acme.test/swagger-ui/index.html")?.startsWith("api-endpoint/swagger_ui/")).toBe(true);
    expect(c("https://documenter.getpostman.com/view/123/foo")?.startsWith("api-endpoint/postman/")).toBe(true);
  });

  it("reads a known platform host before looking for an API marker in its path", () => {
    // A repository that happens to be named "graphql" is a repository.
    expect(c("https://github.com/acme/graphql")).toBe("source-repo/github/profile=https://github.com/acme/graphql");
  });
});

describe("the rest", () => {
  it("passes over an ordinary link", () => {
    expect(c("https://acme.test/about")).toBeNull();
    expect(c("https://cdn.acme.test/app.js")).toBeNull();
    expect(c("mailto:info@acme.test")).toBeNull(); // not an http(s) URL; patterns.ts handles these
    expect(c("ftp://acme.test/x")).toBeNull();
  });
});
