import { describe, expect, it } from "reproxy/testing";
import { exact, fromBody, fromUrl } from "../src/detect";

const found = (ds: { npm: string; version: string }[]) => ds.map((d) => `${d.npm}@${d.version}`);

describe("fromUrl", () => {
  it("reads the public CDNs' paths", () => {
    expect(found(fromUrl("cdnjs.cloudflare.com", "/ajax/libs/jquery/3.5.1/jquery.min.js"))).toEqual(["jquery@3.5.1"]);
    expect(found(fromUrl("cdnjs.cloudflare.com", "/ajax/libs/twitter-bootstrap/4.6.0/js/bootstrap.min.js"))).toEqual(["bootstrap@4.6.0"]);
    expect(found(fromUrl("ajax.googleapis.com", "/ajax/libs/angularjs/1.8.2/angular.min.js"))).toEqual(["angular@1.8.2"]);
    expect(found(fromUrl("cdn.jsdelivr.net", "/npm/vue@2.6.14/dist/vue.min.js"))).toEqual(["vue@2.6.14"]);
    expect(found(fromUrl("unpkg.com", "/@popperjs/core@2.11.8/dist/umd/popper.min.js"))).toEqual(["@popperjs/core@2.11.8"]);
    expect(found(fromUrl("cdn.datatables.net", "/1.10.21/js/jquery.dataTables.min.js"))).toEqual(["datatables.net@1.10.21"]);
  });

  it("reads versioned file and directory names on any host", () => {
    expect(found(fromUrl("app.test", "/js/jquery-1.12.4.min.js"))).toEqual(["jquery@1.12.4"]);
    expect(found(fromUrl("app.test", "/js/jquery-ui-1.12.1.custom.min.js"))).toEqual([]);
    expect(found(fromUrl("app.test", "/js/jquery-ui-1.12.1.min.js"))).toEqual(["jquery-ui@1.12.1"]);
    expect(found(fromUrl("app.test", "/js/react-dom-16.14.0-production.min.js"))).toEqual(["react-dom@16.14.0"]);
    expect(found(fromUrl("app.test", "/vendor/bootstrap/4.6.0/js/bootstrap.bundle.min.js"))).toEqual(["bootstrap@4.6.0"]);
    expect(found(fromUrl("code.jquery.com", "/jquery-3.6.0.slim.min.js"))).toEqual(["jquery@3.6.0"]);
  });

  it("finds nothing in a URL with no version, or on another CDN tree", () => {
    expect(fromUrl("app.test", "/js/jquery.min.js")).toEqual([]);
    expect(fromUrl("app.test", "/static/js/app-1.2.3.js")).toEqual([]);
    expect(fromUrl("cdn.jsdelivr.net", "/gh/someone/repo@1.0.0/x.js")).toEqual([]);
    expect(fromUrl("cdn.jsdelivr.net", "/npm/jquery@3/dist/jquery.min.js")).toEqual([]);
  });
});

describe("fromBody", () => {
  it("reads banner comments", () => {
    expect(found(fromBody("/*! jQuery v3.5.1 | (c) JS Foundation and other contributors | jquery.org/license */\n!function(e,t){}"))).toEqual(["jquery@3.5.1"]);
    expect(found(fromBody("/*!\n * Bootstrap v4.6.0 (https://getbootstrap.com/)\n */"))).toEqual(["bootstrap@4.6.0"]);
    expect(found(fromBody("/**\n * @license AngularJS v1.8.2\n * (c) 2010-2020 Google LLC. http://angularjs.org\n */"))).toEqual(["angular@1.8.2"]);
    expect(found(fromBody("//! moment.js\n//! version : 2.29.1\n//! authors : Tim Wood"))).toEqual(["moment@2.29.1"]);
    expect(found(fromBody('const pdfjsVersion = "2.6.347";'))).toEqual(["pdfjs-dist@2.6.347"]);
  });

  it("reads the version a minified build sets, beside what only that library sets with it", () => {
    expect(found(fromBody('Cn.each=nu,An.VERSION="4.17.15",r("bind bindKey curry curryRight partial".split(" ")'))).toEqual(["lodash@4.17.15"]);
    expect(found(fromBody('e.DOMPurify=t();if(t.version="2.0.8",t.removed=[],!e||!e.document)'))).toEqual(["dompurify@2.0.8"]);
    expect(found(fromBody('e.moment=t();f.version="2.29.1",e=Tt,f.fn=pn,f.min=function(){}'))).toEqual(["moment@2.29.1"]);
    expect(found(fromBody('tinymce={majorVersion:"5",minorVersion:"10.9",releaseDate:"2023"}'))).toEqual(["tinymce@5.10.9"]);
    expect(found(fromBody('var Backbone;h.VERSION="1.4.1";h.$=e;'))).toEqual(["backbone@1.4.1"]);
    // A version set with nothing of the library's own beside it says nothing.
    expect(fromBody('DOMPurify;x.version="2.0.8";')).toEqual([]);
  });

  it("reads Video.js's banner, not the versions its warnings name", () => {
    const body = "/**\n * @license\n * Video.js 7.21.1 <http://videojs.com/>\n */ warn(\"deprecated as of Video.js 7.22.0 and removed in Video.js 8.0.0\")";
    expect(found(fromBody(body))).toEqual(["video.js@7.21.1"]);
  });

  it("finds every library in a bundle", () => {
    const bundle = "/*! jQuery v1.12.4 | (c) jQuery Foundation */\n...\n/*! DOMPurify 2.0.8 | (c) Cure53 */\n...";
    expect(found(fromBody(bundle))).toEqual(["jquery@1.12.4", "dompurify@2.0.8"]);
  });

  it("tells React from React DOM", () => {
    expect(found(fromBody("/** @license React v16.14.0\n * react.production.min.js\n *"))).toEqual(["react@16.14.0"]);
    expect(found(fromBody("/** @license React v16.14.0\n * react-dom.production.min.js\n *"))).toEqual(["react-dom@16.14.0"]);
  });

  it("doesn't take a version named in passing for the library's own", () => {
    // Lodash's banner names the Underscore it was based on.
    expect(fromBody("/**\n * @license\n * Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE\n */")).toEqual([]);
    expect(fromBody("// This plugin requires jQuery v1.7 or later")).toEqual([]);
    expect(fromBody("function f(){return 1}")).toEqual([]);
  });
});

describe("exact", () => {
  it("wants three numbers", () => {
    expect(exact("3.5.1")).toBe(true);
    expect(exact("3.0.0-rc.1")).toBe(true);
    expect(exact("3.5")).toBe(false);
  });
});
