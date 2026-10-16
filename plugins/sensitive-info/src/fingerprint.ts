// Response headers that tell an attacker what the site runs on: the web
// server and its version, the language and framework, the CMS, the proxies
// in front of it, the build that is deployed, the internal host that
// answered, and debugging aids left switched on.
//
// None of it is a secret, and none of it is a vulnerability on its own, but
// it is what turns "find a way in" into "look up the CVEs for Apache
// 2.4.41", so each is a finding the tester can act on (and the developer
// can usually switch off with one setting, which the notes name).
//
// Only response headers are read: a request's headers come from the
// browser, not from the target. A head is small, so this is plain string
// work in the plugin, with no need for text.scan.

import type { FindingType } from "./formats";

export interface Disclosure {
  detector: string;
  label: string;
  /** The finding's value: the header as it was sent, or what it gives away. */
  value: string;
  /** The header it was in. */
  key: string;
  note: string;
  fields?: Record<string, string>;
  /** True when it names a version (see "fingerprint_versions_only"). */
  versioned: boolean;
}

export const FINGERPRINT: FindingType = "fingerprint";

/** The detectors, for the catalog and the settings. */
export const FINGERPRINT_DETECTORS: { id: string; label: string }[] = [
  { id: "server_banner", label: "Web server banner" },
  { id: "tech_header", label: "Language, framework or product header" },
  { id: "app_version", label: "Application build or version header" },
  { id: "proxy_banner", label: "Proxy or gateway banner" },
  { id: "internal_host", label: "Internal host name" },
  { id: "internal_address", label: "Internal IP address" },
  { id: "bigip_cookie", label: "F5 BIG-IP persistence cookie" },
  { id: "stack_cookie", label: "Framework session cookie" },
  { id: "debug_header", label: "Debugging header" },
];

/** A version number: "2.4.41", "10.0", or a version after a slash. */
const VERSION = /(?:\d+\.\d+|\/\s*v?\d)/;

// Headers that name the stack. Names are lower case. Where the header's
// presence is the tell and its value changes from response to response (a
// cache status, a timing, a request ID), the finding's value is the product
// it names, so that one finding gathers every sighting.
const TECH: Record<string, { says: string; product?: string }> = {
  "x-powered-by": { says: "names the language or framework that built the response" },
  "x-aspnet-version": { says: "gives the exact ASP.NET runtime version" },
  "x-aspnetmvc-version": { says: "gives the ASP.NET MVC version" },
  "x-generator": { says: "names the CMS or generator that built the page" },
  "x-powered-cms": { says: "names the CMS" },
  "x-content-powered-by": { says: "names the CMS extension that built the page" },
  "x-craft-powered-by": { says: "names Craft CMS" },
  "x-turbo-charged-by": { says: "names LiteSpeed" },
  "x-mod-pagespeed": { says: "names mod_pagespeed and its version" },
  "x-page-speed": { says: "names ngx_pagespeed and its version" },
  "x-pingback": { says: "points at WordPress's XML-RPC endpoint" },
  "x-umbraco-version": { says: "gives the Umbraco version" },
  "liferay-portal": { says: "gives the Liferay Portal version" },
  "x-jenkins": { says: "gives the Jenkins version" },
  "x-hudson": { says: "gives the Hudson version" },
  "x-owa-version": { says: "gives the Outlook Web Access build, which maps to an Exchange cumulative update" },
  "microsoftsharepointteamservices": { says: "gives the SharePoint build" },
  "x-drupal-cache": { says: "shows the site is Drupal", product: "Drupal" },
  "x-drupal-dynamic-cache": { says: "shows the site is Drupal 8 or later", product: "Drupal 8 or later" },
  "x-litespeed-cache": { says: "shows the site is served by LiteSpeed (often WordPress with LiteSpeed Cache)", product: "LiteSpeed" },
  "x-sharepointhealthscore": { says: "shows the site is SharePoint", product: "SharePoint" },
  "x-confluence-request-time": { says: "shows the site is Confluence", product: "Confluence" },
  "x-arequestid": { says: "shows the site is Jira or another Atlassian product", product: "Atlassian (Jira)" },
  "x-gitlab-meta": { says: "shows the site is GitLab", product: "GitLab" },
  "x-magento-cache-debug": { says: "shows the site is Magento, with its cache debugging on", product: "Magento" },
  "x-magento-tags": { says: "shows the site is Magento", product: "Magento" },
  "x-nextjs-cache": { says: "shows the site is Next.js", product: "Next.js" },
  "x-nextjs-matched-path": { says: "shows the site is Next.js, and the route that answered", product: "Next.js" },
  "x-oracle-dms-ecid": { says: "shows the site runs on Oracle WebLogic or Fusion Middleware", product: "Oracle WebLogic" },
  "x-oracle-dms-rid": { says: "shows the site runs on Oracle WebLogic or Fusion Middleware", product: "Oracle WebLogic" },
  "x-rack-cache": { says: "shows the site is a Ruby (Rack) application", product: "Ruby (Rack)" },
  "x-runtime": { says: "shows the site is probably Ruby on Rails, and how long the request took", product: "Ruby on Rails (probably)" },
  "x-sucuri-id": { says: "shows the site is behind the Sucuri firewall", product: "Sucuri" },
};

const APP_VERSION = [
  "x-version",
  "x-app-version",
  "x-application-version",
  "x-build",
  "x-build-version",
  "x-build-id",
  "x-build-number",
  "x-revision",
  "x-commit",
  "x-commit-sha",
  "x-git-commit",
  "x-git-sha",
  "x-git-revision",
  "x-release",
  "x-deployment-version",
  "x-application-context",
];

const INTERNAL_HOST = [
  "x-backend-server",
  "x-backend",
  "x-backend-host",
  "x-server",
  "x-server-name",
  "x-served-by",
  "x-served-via",
  "x-upstream",
  "x-upstream-server",
  "x-host",
  "x-hostname",
  "x-node",
  "x-node-id",
  "x-node-name",
  "x-instance",
  "x-instance-id",
  "x-pod",
  "x-pod-name",
  "x-container",
  "x-machine",
  "x-feserver",
  "x-beserver",
  "x-calculatedbetarget",
  "x-diaginfo",
  "x-ms-server-fqdn",
  "x-envoy-decorator-operation",
];

/** Gateways that show themselves by a header of their own. */
const PROXY_HEADERS: Record<string, string> = {
  "x-varnish": "Varnish",
  "x-kong-proxy-latency": "Kong",
  "x-kong-upstream-latency": "Kong",
  "x-envoy-upstream-service-time": "Envoy",
  "x-squid-error": "Squid",
};

// Debugging aids. The header's value is usually per request (a profiler
// token), so the finding's value is the aid itself and an example value
// goes in the finding's fields.
const DEBUG: Record<string, { product: string; says: string }> = {
  "x-debug-token": { product: "Symfony profiler", says: "Symfony's profiler is on: the token opens the profile of a request at /_profiler/<token>, with its database queries, configuration and request data." },
  "x-debug-token-link": { product: "Symfony profiler", says: "Symfony's profiler is on, and the header links to a request's profile: its database queries, configuration and request data." },
  "x-debugbar-id": { product: "Laravel Debugbar", says: "Laravel Debugbar is on: it exposes the queries, views and request data of recent requests." },
  "phpdebugbar-id": { product: "PHP Debugbar", says: "PHP Debugbar is on: it exposes the queries and request data of recent requests." },
  "x-clockwork-id": { product: "Laravel Clockwork", says: "Laravel Clockwork is on: /__clockwork/<id> shows a request's queries, logs and data." },
  "x-clockwork-version": { product: "Laravel Clockwork", says: "Laravel Clockwork is on: /__clockwork/ shows recent requests' queries, logs and data." },
  "x-chromelogger-data": { product: "ChromeLogger", says: "Server-side logging is being sent to the browser (ChromeLogger), which can carry variables and stack traces." },
  "x-chromephp-data": { product: "ChromePHP", says: "Server-side logging is being sent to the browser (ChromePHP), which can carry variables and stack traces." },
  "x-debug": { product: "Debug mode", says: "A debug header is set, which usually means a debug mode is on." },
  "x-debug-info": { product: "Debug mode", says: "A debug header is set, which usually means a debug mode is on." },
  "x-xdebug-profile-filename": { product: "Xdebug profiler", says: "Xdebug's profiler is on, and the header names the file it wrote on the server." },
};

/** Session cookies whose names give the framework away. */
const COOKIES: [RegExp, string][] = [
  [/^PHPSESSID$/, "PHP"],
  [/^JSESSIONID$/i, "a Java servlet container (Tomcat, Jetty, WebLogic, WebSphere…)"],
  [/^ASP\.NET_SessionId$/i, "ASP.NET"],
  [/^\.ASPXAUTH$/i, "ASP.NET forms authentication"],
  [/^\.AspNetCore\./, "ASP.NET Core"],
  [/^ASPSESSIONID[A-Z]{8}$/, "classic ASP on IIS"],
  [/^(?:CFID|CFTOKEN)$/i, "Adobe ColdFusion"],
  [/^laravel_session$/, "Laravel"],
  [/^ci_session$/, "CodeIgniter"],
  [/^connect\.sid$/, "Express (Node.js)"],
  [/^rack\.session$/, "a Ruby (Rack) application"],
  [/^_[a-z0-9_]+_session$/, "Ruby on Rails"],
  [/^(?:csrftoken|django_language)$/, "Django"],
  [/^SS?ESS[0-9a-f]{32}$/, "Drupal"],
  [/^(?:wordpress_logged_in_|wordpress_sec_|wp-settings-)/, "WordPress"],
  [/^PrestaShop-[0-9a-f]{32}$/, "PrestaShop"],
  [/^_shibsession_/, "Shibboleth single sign-on"],
  [/^X-Magento-Vary$/, "Magento"],
  [/^__RequestVerificationToken/, "ASP.NET MVC"],
  [/^(?:XSRF-TOKEN)$/, ""], // Angular and Laravel both: not telling enough
];

/** Read the disclosures in a response's head (its status line and headers). */
export function disclosures(head: string): Disclosure[] {
  const out: Disclosure[] = [];
  const seen: Record<string, boolean> = {};
  const add = (d: Disclosure) => {
    if (seen[d.value]) return;
    seen[d.value] = true;
    out.push(d);
  };
  const lines = head.split(/\r?\n/);
  for (let i = 1; i < lines.length; i++) {
    const colon = lines[i].indexOf(":");
    if (colon <= 0) continue;
    // HTTP/2 sends names in lower case: written the usual way, the same
    // header makes the same finding over either protocol.
    const name = canonical(lines[i].slice(0, colon).trim());
    const value = lines[i].slice(colon + 1).trim();
    if (!value) continue;
    const lower = name.toLowerCase();
    const line = `${name}: ${value}`;
    const versioned = VERSION.test(value);

    if (lower === "server") {
      add({
        detector: "server_banner",
        label: "Web server banner",
        value: line,
        key: name,
        versioned,
        note: versioned
          ? "The Server header names the web server and its exact version, which lets anyone look up the vulnerabilities that version has. Turn the version off (ServerTokens Prod and ServerSignature Off in Apache, server_tokens off in nginx, removeServerHeader in IIS)."
          : "The Server header names the web server or service in front of the site. It is a small disclosure on its own, but it narrows what an attacker needs to try.",
      });
    } else if (TECH[lower] !== undefined) {
      const t = TECH[lower];
      const v = !t.product && versioned;
      add({
        detector: "tech_header",
        label: "Technology disclosure",
        value: t.product ? `${t.product} (${name} header)` : line,
        key: name,
        versioned: v,
        note: `The ${name} header ${t.says}${v ? ", with a version that can be checked against known vulnerabilities" : ""}. The browser doesn't need it; remove it (expose_php = Off for PHP's X-Powered-By, app.disable('x-powered-by') in Express, enableVersionHeader="false" and removing X-Powered-By in IIS for ASP.NET).`,
        fields: t.product ? { header: line } : undefined,
      });
    } else if (APP_VERSION.indexOf(lower) >= 0) {
      add({
        detector: "app_version",
        label: "Application build disclosure",
        value: line,
        key: name,
        versioned: true,
        note:
          lower === "x-application-context"
            ? "Spring Boot's X-Application-Context header gives the application's name, its active profiles and often the port it listens on internally. Remove it (management.server.add-application-context-header=false)."
            : `The ${name} header gives the build that is deployed. It tells an attacker when the site changes and which release to study, and a commit ID can be matched against a public repository.`,
      });
    } else if (lower === "x-served-by" && /^cache-[a-z0-9-]+(?:\s*,\s*cache-[a-z0-9-]+)*$/i.test(value)) {
      // Fastly names the cache nodes that served the response: its own
      // edge, not the site's servers, and different on every request.
      add({
        detector: "proxy_banner",
        label: "Proxy banner",
        value: "Fastly (X-Served-By header)",
        key: name,
        versioned: false,
        note: "The X-Served-By header names Fastly cache nodes: the site is behind Fastly's CDN. Knowing the CDN narrows the cache poisoning and request smuggling techniques worth trying, and the origin behind it may be reachable directly.",
        fields: { header: line },
      });
    } else if (INTERNAL_HOST.indexOf(lower) >= 0) {
      add({
        detector: "internal_host",
        label: "Internal host disclosure",
        value: line,
        key: name,
        versioned: false,
        note: `The ${name} header names the server or node behind the front end that answered. Internal host names map out the infrastructure, and are what a server-side request forgery or a host header attack aims at.`,
      });
    } else if (lower === "via") {
      // Via is a protocol header; it only gives anything away when it names the software.
      if (/[a-z]{3,}/i.test(value.replace(/^\s*[\d.]+\s+/, "").replace(/\b(?:HTTP|https?)\b/gi, ""))) {
        add({
          detector: "proxy_banner",
          label: "Proxy banner",
          value: line,
          key: name,
          versioned,
          note: "The Via header names the proxies the response passed through" + (versioned ? ", with their versions" : "") + ". It maps the infrastructure in front of the application, and an old proxy version can be attacked in its own right (request smuggling, cache poisoning).",
        });
      }
    } else if (PROXY_HEADERS[lower] !== undefined) {
      add({
        detector: "proxy_banner",
        label: "Proxy banner",
        value: `${PROXY_HEADERS[lower]} (${name} header)`,
        key: name,
        versioned: false,
        note: `The ${name} header shows the response passed through ${PROXY_HEADERS[lower]}. Knowing the proxy narrows the request smuggling and cache poisoning techniques worth trying.`,
      });
    } else if (DEBUG[lower] !== undefined) {
      add({
        detector: "debug_header",
        label: "Debugging enabled",
        value: `${DEBUG[lower].product} (${name} header)`,
        key: name,
        versioned: false,
        note: DEBUG[lower].says + " Debugging aids should never be on in production.",
        fields: { example: line },
      });
    } else if (lower === "set-cookie") {
      cookie(name, value, add);
    }

    // An internal address in any header: a Location pointing inside, a
    // Via or X-Forwarded-For echoed back, a node's own address.
    if (lower !== "set-cookie") {
      for (const ip of privateAddresses(value)) {
        add({
          detector: "internal_address",
          label: "Internal IP address",
          value: ip,
          key: name,
          versioned: false,
          note: `The ${name} header carries ${ip}, an address on a private network. It shows how the network behind the site is laid out, and is a target worth trying for server-side request forgery.`,
          fields: { header: line },
        });
      }
    }
  }
  return out;
}

/** A header name written the usual way: x-powered-by → X-Powered-By. */
function canonical(name: string): string {
  return name
    .split("-")
    .map((p) => (p ? p.charAt(0).toUpperCase() + p.slice(1).toLowerCase() : p))
    .join("-");
}

function cookie(header: string, value: string, add: (d: Disclosure) => void): void {
  const eq = value.indexOf("=");
  if (eq <= 0) return;
  const name = value.slice(0, eq).trim();
  const content = value.slice(eq + 1).split(";")[0].trim();

  // F5 BIG-IP's persistence cookie encodes the pool member's address.
  if (/^BIGipServer/i.test(name)) {
    const member = decodeBigIP(content);
    add({
      detector: "bigip_cookie",
      label: "F5 BIG-IP pool member",
      value: member ? `${member} (${name})` : name,
      key: header,
      versioned: false,
      note: member
        ? `The ${name} cookie is F5 BIG-IP's load balancer persistence cookie, and it encodes the internal address of the server behind it: ${member}. It also names the pool. Encrypt it (cookie encryption in the persistence profile).`
        : `The ${name} cookie shows the site is behind an F5 BIG-IP load balancer, and names the pool.`,
      fields: member ? { pool: name.slice("BIGipServer".length), member } : undefined,
    });
    return;
  }
  for (const [re, tech] of COOKIES) {
    if (!re.test(name)) continue;
    if (!tech) return;
    add({
      detector: "stack_cookie",
      label: "Framework session cookie",
      value: `${name} cookie (${tech})`,
      key: header,
      versioned: false,
      note: `The ${name} cookie is the default session cookie of ${tech}, which tells an attacker what the application is built with. Renaming the session cookie removes the hint.`,
    });
    return;
  }
}

/**
 * The address a BIG-IP persistence cookie holds, as "10.1.2.3:8080", or
 * undefined if it isn't the unencrypted form: "<ip>.<port>.0000" for IPv4
 * (both numbers little-endian), "rd<n>o00000000000000000000ffff<hex ip>o<port>"
 * for IPv4 in a route domain, and "vi<hex ipv6>.<port>" for IPv6.
 */
export function decodeBigIP(v: string): string | undefined {
  let m = /^(\d{1,10})\.(\d{1,5})\.0000$/.exec(v);
  if (m) {
    const n = Number(m[1]);
    const p = Number(m[2]);
    if (n > 0xffffffff || p > 0xffff) return undefined;
    const ip = [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff].join(".");
    return `${ip}:${((p & 0xff) << 8) | (p >>> 8)}`;
  }
  m = /^rd\d+o0{20}ffff([0-9a-f]{8})o(\d{1,5})$/i.exec(v);
  if (m) {
    const ip = [0, 2, 4, 6].map((i) => parseInt(m![1].slice(i, i + 2), 16)).join(".");
    return `${ip}:${m[2]}`;
  }
  m = /^vi([0-9a-f]{32})\.(\d{1,5})$/i.exec(v);
  if (m) {
    const groups = m[1].match(/.{4}/g)!.map((g) => g.replace(/^0+(?=.)/, ""));
    const p = Number(m[2]);
    return `[${groups.join(":")}]:${((p & 0xff) << 8) | (p >>> 8)}`;
  }
  return undefined;
}

/** The private, loopback and link-local IPv4 addresses in a header's value. */
export function privateAddresses(value: string): string[] {
  const out: string[] = [];
  const re = /(?:^|[^\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.]*\d)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(value))) {
    const ip = m[1];
    const o = ip.split(".").map(Number);
    if (o.some((x) => x > 255)) continue;
    const internal =
      o[0] === 10 ||
      (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
      (o[0] === 192 && o[1] === 168) ||
      (o[0] === 100 && o[1] >= 64 && o[1] <= 127) || // carrier-grade NAT, used inside clouds
      (o[0] === 169 && o[1] === 254) ||
      o[0] === 127;
    if (internal && out.indexOf(ip) < 0) out.push(ip);
  }
  return out;
}
