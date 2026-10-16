// How each JavaScript library gives its version away, and the npm package
// osv.dev knows it by.
//
// Written for this plugin rather than copied from a scanner's database.
// A rule is kept only when it is specific to its library: a banner comment
// in the form the library's own builds print it, or a property only that
// library sets. Generic shapes ("VERSION = '1.2.3'", "@version 1.2.3") are
// left out on purpose: a bundle holds many libraries, and a version pinned
// on the wrong one is a false finding.
//
// Each content rule has a needle, a plain string the body must contain
// before the rule's regular expression is run at all (see detect.ts), and a
// pattern in RE2 syntax (it runs in Go, through text.scan) whose groups
// are the version (two groups, as TinyMCE gives it, are joined with a dot).
//
// Banners are the first choice. Where a minified build drops its banner,
// the rule matches the statement that sets the library's version together
// with the statement the library's own code puts beside it (DOMPurify's
// version is followed by its "removed" list), never "x.version" alone.

/** A version: two or three numbers, and a pre-release tag if there is one. */
export const V = String.raw`(\d{1,4}\.\d{1,4}(?:\.\d{1,6})?(?:-[0-9A-Za-z][0-9A-Za-z.]{0,30})?)`;

export interface Library {
  /** The npm package, as osv.dev's npm ecosystem names it. */
  npm: string;
  /** How people name it. */
  name: string;
  /** The rules for finding its version in a script's text. */
  content?: { needle: string; pattern: string }[];
  /** File names it is published under (jquery-3.5.1.min.js → "jquery"). */
  files?: string[];
  /** Directory names it is published under (/bootstrap/4.6.0/…). */
  dirs?: string[];
}

export const libraries: Library[] = [
  {
    npm: "jquery",
    name: "jQuery",
    content: [
      { needle: "jQuery v", pattern: String.raw`/\*!? jQuery v${V}` },
      { needle: "jQuery JavaScript Library v", pattern: String.raw`jQuery JavaScript Library v${V}` },
    ],
    files: ["jquery"],
    dirs: ["jquery"],
  },
  {
    npm: "jquery-ui",
    name: "jQuery UI",
    content: [{ needle: "jQuery UI - v", pattern: String.raw`jQuery UI - v${V}` }],
    files: ["jquery-ui"],
    dirs: ["jquery-ui", "jqueryui"],
  },
  {
    npm: "jquery-migrate",
    name: "jQuery Migrate",
    content: [{ needle: "jQuery Migrate", pattern: String.raw`jQuery Migrate (?:- )?v${V}` }],
    files: ["jquery-migrate"],
  },
  {
    npm: "jquery-validation",
    name: "jQuery Validation",
    content: [{ needle: "jQuery Validation Plugin", pattern: String.raw`jQuery Validation Plugin - v${V}` }],
    files: ["jquery.validate"],
  },
  {
    npm: "bootstrap",
    name: "Bootstrap",
    content: [{ needle: "getbootstrap.com", pattern: String.raw`Bootstrap v${V} \(https?://getbootstrap\.com` }],
    files: ["bootstrap"],
    dirs: ["bootstrap"],
  },
  {
    npm: "angular",
    name: "AngularJS",
    content: [{ needle: "AngularJS v", pattern: String.raw`AngularJS v${V}` }],
    files: ["angular", "angularjs"],
    dirs: ["angularjs"],
  },
  {
    npm: "@angular/core",
    name: "Angular",
    content: [{ needle: "@license Angular v", pattern: String.raw`@license Angular v${V}` }],
  },
  {
    npm: "react",
    name: "React",
    // The banner names the file it heads: react.production.min.js.
    content: [{ needle: "@license React v", pattern: String.raw`@license React v${V}[\s*]+react\.(?:production|development|profiling)` }],
    files: ["react"],
  },
  {
    npm: "react-dom",
    name: "React DOM",
    content: [{ needle: "@license React v", pattern: String.raw`@license React v${V}[\s*]+react-dom\.(?:production|development|profiling)` }],
    files: ["react-dom"],
  },
  {
    npm: "vue",
    name: "Vue.js",
    content: [
      { needle: "Vue.js v", pattern: String.raw`Vue\.js v${V}` },
      { needle: "vue v", pattern: String.raw`\* vue v${V}` },
    ],
    files: ["vue"],
  },
  {
    npm: "lodash",
    name: "Lodash",
    // Only the old banners carry a version (later ones are "Lodash
    // <https://lodash.com/>"), so 4.x is found where it sets its VERSION.
    content: [
      { needle: "odash", pattern: String.raw`@license\s+(?:\*\s+)?(?:Lo-Dash|lodash|Lodash) v?${V}` },
      { needle: "Used as the semantic version number", pattern: String.raw`Used as the semantic version number\. \*/\s*var VERSION = ["']${V}["']` },
      // Minified: An.VERSION="4.17.15",r("bind bindKey curry curryRight …
      { needle: "bindKey curry", pattern: String.raw`\.VERSION\s*=\s*["']${V}["']\s*,\s*\w+\(\s*["']bind bindKey curry` },
    ],
    files: ["lodash"],
  },
  {
    npm: "underscore",
    name: "Underscore.js",
    // Lodash's banner names the Underscore it was based on, so the URL on
    // the next line is required.
    content: [{ needle: "Underscore.js", pattern: String.raw`Underscore\.js ${V}\s*\n\s*//\s*https?://underscorejs\.org` }],
    files: ["underscore"],
  },
  {
    npm: "moment",
    name: "Moment.js",
    content: [
      { needle: "//! moment.js", pattern: String.raw`//! moment\.js\s*\n//! version : ${V}` },
      { needle: "hooks.version", pattern: String.raw`hooks\.version\s*=\s*["']${V}["']` },
      // Minified: f.version="2.29.1",e=Tt,f.fn=pn,f.min=…
      { needle: ".fn=", pattern: String.raw`\.version\s*=\s*["']${V}["']\s*,\s*\w+\s*=\s*\w+\s*,\s*\w+\.fn\s*=\s*\w+\s*,\s*\w+\.min\s*=` },
    ],
    files: ["moment"],
  },
  {
    npm: "moment-timezone",
    name: "Moment Timezone",
    content: [{ needle: "//! moment-timezone.js", pattern: String.raw`//! moment-timezone\.js\s*\n//! version : ${V}` }],
  },
  {
    npm: "handlebars",
    name: "Handlebars",
    content: [{ needle: "handlebars v", pattern: String.raw`handlebars v${V}` }],
    files: ["handlebars"],
  },
  {
    npm: "dompurify",
    name: "DOMPurify",
    content: [
      { needle: "DOMPurify ", pattern: String.raw`DOMPurify ${V}` },
      { needle: "DOMPurify.version", pattern: String.raw`DOMPurify\.version\s*=\s*["']${V}["']` },
      // Minified: t.version="2.0.8",t.removed=[]
      { needle: "DOMPurify", pattern: String.raw`\.version\s*=\s*["']${V}["']\s*,\s*\w+\.removed\s*=\s*\[\]` },
    ],
    files: ["purify"],
  },
  {
    npm: "axios",
    name: "Axios",
    content: [{ needle: "Axios v", pattern: String.raw`Axios v${V}` }],
    files: ["axios"],
  },
  {
    npm: "backbone",
    name: "Backbone.js",
    content: [
      { needle: "Backbone.js ", pattern: String.raw`Backbone\.js ${V}` },
      { needle: "Backbone.VERSION", pattern: String.raw`Backbone\.VERSION\s*=\s*["']${V}["']` },
      // Minified: h.VERSION="1.4.1";h.$=e;
      { needle: "Backbone", pattern: String.raw`\.VERSION\s*=\s*["']${V}["']\s*[;,]\s*\w+\.\$\s*=` },
    ],
    files: ["backbone"],
  },
  {
    npm: "knockout",
    name: "Knockout",
    content: [
      { needle: "Knockout JavaScript library v", pattern: String.raw`Knockout JavaScript library v${V}` },
      // ko.version = "3.5.1"; ko.exportSymbol('version', ko.version), minified as _.b("version",_.version).
      { needle: "\"version\"", pattern: String.raw`\.version\s*=\s*["']${V}["'][;,\s]*\w+\.(?:b|exportSymbol)\(\s*["']version["']` },
      { needle: "'version'", pattern: String.raw`\.version\s*=\s*["']${V}["'][;,\s]*\w+\.(?:b|exportSymbol)\(\s*["']version["']` },
    ],
    files: ["knockout"],
  },
  {
    npm: "d3",
    name: "D3",
    content: [{ needle: "d3js.org v", pattern: String.raw`d3js\.org v${V}` }],
    files: ["d3"],
  },
  {
    npm: "chart.js",
    name: "Chart.js",
    content: [{ needle: "Chart.js v", pattern: String.raw`Chart\.js v${V}` }],
  },
  {
    npm: "select2",
    name: "Select2",
    content: [{ needle: "Select2 ", pattern: String.raw`/\*!? Select2 ${V}` }],
    files: ["select2"],
  },
  {
    npm: "datatables.net",
    name: "DataTables",
    // The banner's version line: "/*! DataTables 1.10.21" or, in the
    // minified build, " DataTables 1.10.21" on a line of its own.
    content: [{ needle: "DataTables ", pattern: String.raw`(?m)(?:/\*!?\s*|^\s*)DataTables ${V}` }],
  },
  {
    npm: "tinymce",
    name: "TinyMCE",
    content: [
      { needle: "TinyMCE version ", pattern: String.raw`TinyMCE version ${V}` },
      { needle: "minorVersion", pattern: String.raw`majorVersion\s*:\s*["'](\d{1,3})["']\s*,\s*minorVersion\s*:\s*["'](\d{1,4}\.\d{1,4})["']` },
    ],
  },
  {
    npm: "ckeditor4",
    name: "CKEditor 4",
    content: [{ needle: "CKEDITOR", pattern: String.raw`timestamp\s*:\s*"[^"]{0,20}"\s*,\s*version\s*:\s*"${V}` }],
  },
  {
    npm: "highcharts",
    name: "Highcharts",
    content: [{ needle: "Highcharts JS v", pattern: String.raw`Highcharts JS v${V}` }],
  },
  {
    npm: "@popperjs/core",
    name: "Popper",
    content: [{ needle: "@popperjs/core v", pattern: String.raw`@popperjs/core v${V}` }],
  },
  {
    npm: "sweetalert2",
    name: "SweetAlert2",
    content: [{ needle: "sweetalert2 v", pattern: String.raw`sweetalert2 v${V}` }],
  },
  {
    npm: "socket.io-client",
    name: "Socket.IO client",
    content: [{ needle: "Socket.IO v", pattern: String.raw`Socket\.IO v${V}` }],
  },
  {
    npm: "video.js",
    name: "Video.js",
    // The banner, not the deprecation warnings ("as of Video.js 7.22.0").
    content: [{ needle: "Video.js ", pattern: String.raw`\* Video\.js ${V} <` }],
  },
  {
    npm: "marked",
    name: "marked",
    content: [{ needle: "marked v", pattern: String.raw`\* marked v${V}` }],
  },
  {
    npm: "js-cookie",
    name: "JavaScript Cookie",
    content: [
      { needle: "JavaScript Cookie v", pattern: String.raw`JavaScript Cookie v${V}` },
      { needle: "js-cookie v", pattern: String.raw`js-cookie v${V}` },
    ],
    files: ["js.cookie"],
  },
  {
    npm: "swiper",
    name: "Swiper",
    content: [{ needle: "Swiper ", pattern: String.raw`Swiper ${V}\s*\n\s*\*\s*Most modern` }],
  },
  {
    npm: "pdfjs-dist",
    name: "PDF.js",
    content: [
      { needle: "pdfjsVersion", pattern: String.raw`pdfjsVersion\s*=\s*["']${V}["']` },
      // The version the display layer asks the worker for.
      { needle: "GetDocRequest", pattern: String.raw`"GetDocRequest"\s*,\s*\{\s*docId\s*:\s*\w+\s*,\s*apiVersion\s*:\s*["']${V}["']` },
    ],
  },
  {
    npm: "core-js",
    name: "core-js",
    content: [
      { needle: "Denis Pushkarev", pattern: String.raw`\* core-js ${V}` },
      { needle: "Denis Pushkarev", pattern: String.raw`version\s*:\s*["']${V}["']\s*,\s*mode\s*:` },
    ],
  },
];

/**
 * cdnjs's (and Google's /ajax/libs/) names for libraries whose npm package
 * is named differently. Any other cdnjs name is taken to be the npm name,
 * which it usually is: cdnjs builds most libraries from npm.
 */
export const cdnjsNames: Record<string, string> = {
  "twitter-bootstrap": "bootstrap",
  "angular.js": "angular",
  "angularjs": "angular",
  "lodash.js": "lodash",
  "moment.js": "moment",
  "underscore.js": "underscore",
  "handlebars.js": "handlebars",
  "backbone.js": "backbone",
  "knockout": "knockout",
  "jqueryui": "jquery-ui",
  "jquery-validate": "jquery-validation",
  "socket.io": "socket.io-client",
  "pdf.js": "pdfjs-dist",
  "datatables": "datatables.net",
  "ckeditor": "ckeditor4",
  "dompurify": "dompurify",
};

/** The library an npm package is, if it is one listed here. */
export function libraryOf(npm: string): Library | undefined {
  return libraries.find((l) => l.npm === npm);
}

/** How a package is named in findings: "jQuery", or the package itself. */
export function displayName(npm: string): string {
  return libraryOf(npm)?.name ?? npm;
}
