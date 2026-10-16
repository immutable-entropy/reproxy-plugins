import { describe, it, expect, mock } from "reproxy/testing";
import { scan, type Options } from "../src/detectors";
import { decodeBigIP, disclosures, privateAddresses } from "../src/fingerprint";
import { load } from "../main";

const base: Options = {
  detectors: [],
  skip: [],
  minEntropy: 3.5,
  maxBody: 1 << 20,
  maxPii: 1 << 20,
  ignoreEmails: [],
  ignoreValues: [],
  hexHashes: false,
  maxHits: 100,
};

const head = (...lines: string[]) => ["HTTP/1.1 200 OK", ...lines].join("\r\n") + "\r\n\r\n";
const found = (h: string) => disclosures(h).map((d) => `${d.detector}=${d.value}`);

describe("disclosures", () => {
  it("reads server, language and framework banners", () => {
    expect(
      found(head("Server: Apache/2.4.41 (Ubuntu)", "X-Powered-By: PHP/7.4.3", "X-AspNet-Version: 4.0.30319", "X-Generator: Drupal 9 (https://www.drupal.org)")),
    ).toEqual([
      "server_banner=Server: Apache/2.4.41 (Ubuntu)",
      "tech_header=X-Powered-By: PHP/7.4.3",
      "tech_header=X-Aspnet-Version: 4.0.30319",
      "tech_header=X-Generator: Drupal 9 (https://www.drupal.org)",
    ]);
  });

  it("says whether a banner names a version", () => {
    const [bare, versioned] = disclosures(head("Server: nginx", "X-Powered-By: Express/4.17"));
    expect(bare.versioned).toBe(false);
    expect(bare.note).not.toContain("exact version");
    expect(versioned.versioned).toBe(true);
  });

  it("reads builds, internal hosts, proxies and debugging aids", () => {
    expect(
      found(
        head(
          "X-Application-Context: billing:prod:8081",
          "X-Backend-Server: web-03.corp.internal",
          "Via: 1.1 varnish (Varnish/6.0)",
          "X-Kong-Proxy-Latency: 2",
          "X-Debug-Token: a1b2c3",
          "X-Debug-Token-Link: https://app.test/_profiler/a1b2c3",
        ),
      ),
    ).toEqual([
      "app_version=X-Application-Context: billing:prod:8081",
      "internal_host=X-Backend-Server: web-03.corp.internal",
      "proxy_banner=Via: 1.1 varnish (Varnish/6.0)",
      "proxy_banner=Kong (X-Kong-Proxy-Latency header)",
      "debug_header=Symfony profiler (X-Debug-Token header)",
      "debug_header=Symfony profiler (X-Debug-Token-Link header)",
    ]);
  });

  it("finds internal addresses in any header", () => {
    expect(found(head("Location: http://10.20.30.40:8080/login", "X-Forwarded-For: 203.0.113.9, 192.168.1.15"))).toEqual([
      "internal_address=10.20.30.40",
      "internal_address=192.168.1.15",
    ]);
    expect(privateAddresses("172.15.0.1 172.16.0.1 172.31.255.255 172.32.0.1 8.8.8.8 1.10.0.0.1")).toEqual(["172.16.0.1", "172.31.255.255"]);
  });

  it("names the framework behind a session cookie, never its value", () => {
    const got = found(
      head(
        "Set-Cookie: PHPSESSID=abc123; path=/",
        "Set-Cookie: JSESSIONID=XYZ; Path=/; HttpOnly",
        "Set-Cookie: laravel_session=eyJpdiI6; path=/",
        "Set-Cookie: theme=dark",
        "Set-Cookie: XSRF-TOKEN=abc",
      ),
    );
    expect(got).toEqual([
      "stack_cookie=PHPSESSID cookie (PHP)",
      "stack_cookie=JSESSIONID cookie (a Java servlet container (Tomcat, Jetty, WebLogic, WebSphere…))",
      "stack_cookie=laravel_session cookie (Laravel)",
    ]);
  });

  it("decodes the internal address in a BIG-IP cookie", () => {
    // 10.1.1.100:8080, as BIG-IP writes it (both numbers little-endian).
    expect(decodeBigIP("1677787402.36895.0000")).toBe("10.1.1.100:8080");
    expect(decodeBigIP("rd5o00000000000000000000ffffc0000201o80")).toBe("192.0.2.1:80");
    expect(decodeBigIP("vi20010db8000000000000000000000001.20480")).toBe("[2001:db8:0:0:0:0:0:1]:80");
    expect(decodeBigIP("!abcEncryptedValue")).toBeUndefined();
    const [d] = disclosures(head("Set-Cookie: BIGipServerpool_web=1677787402.36895.0000; path=/"));
    expect(d.value).toBe("10.1.1.100:8080 (BIGipServerpool_web)");
    expect(d.fields).toEqual({ pool: "pool_web", member: "10.1.1.100:8080" });
  });

  it("writes header names the same way whatever the protocol", () => {
    expect(found(head("server: nginx/1.18.0", "x-powered-by: Express"))).toEqual(["server_banner=Server: nginx/1.18.0", "tech_header=X-Powered-By: Express"]);
  });

  it("names the product, not a value that changes on every response", () => {
    const a = found(head("X-Drupal-Cache: MISS", "X-Runtime: 0.012345", "X-Debug-Token: aaa111"));
    const b = found(head("X-Drupal-Cache: HIT", "X-Runtime: 0.098765", "X-Debug-Token: bbb222"));
    expect(a).toEqual(b);
    expect(a).toEqual([
      "tech_header=Drupal (X-Drupal-Cache header)",
      "tech_header=Ruby on Rails (probably) (X-Runtime header)",
      "debug_header=Symfony profiler (X-Debug-Token header)",
    ]);
    expect(disclosures(head("X-Debug-Token: aaa111"))[0].fields).toEqual({ example: "X-Debug-Token: aaa111" });
  });

  it("takes Fastly's cache nodes for the CDN, not internal hosts", () => {
    expect(found(head("X-Served-By: cache-hel1410034-HEL, cache-lga-kjfk8660034-LGA"))).toEqual(["proxy_banner=Fastly (X-Served-By header)"]);
    expect(found(head("X-Served-By: app-node-7.prod.internal"))).toEqual(["internal_host=X-Served-By: app-node-7.prod.internal"]);
  });

  it("leaves ordinary headers alone", () => {
    expect(found(head("Content-Type: text/html", "Cache-Control: no-store", "Via: 1.1", "Date: Tue, 01 Jan 2030 00:00:00 GMT"))).toEqual([]);
  });
});

describe("scan", () => {
  it("reads a response's headers, not a request's", () => {
    const h = head("Server: Apache/2.4.41");
    expect(scan({ side: "response", head: h }, base).map((x) => x.type)).toEqual(["fingerprint"]);
    expect(scan({ side: "request", head: "GET / HTTP/1.1\r\nServer: Apache/2.4.41\r\n\r\n" }, base)).toEqual([]);
  });

  it("records a disclosure readable, never hidden", () => {
    const [hit] = scan({ side: "response", head: head("X-Powered-By: PHP/7.4.3") }, base);
    expect(hit.secret).toBe(false);
  });

  it("drops bare banners when only versions are wanted, and the whole category when skipped", () => {
    const h = head("Server: nginx", "X-Powered-By: PHP/8.1.2", "X-Backend-Server: web-03");
    expect(scan({ side: "response", head: h }, { ...base, versionsOnly: true }).map((x) => x.detector)).toEqual(["tech_header", "internal_host"]);
    expect(scan({ side: "response", head: h }, { ...base, skip: ["fingerprint"] })).toEqual([]);
    expect(scan({ side: "response", head: h }, { ...base, detectors: ["server_banner"] }).map((x) => x.detector)).toEqual(["server_banner"]);
  });
});

describe("recording", () => {
  it("records a disclosure once per host, with notes that merge", async () => {
    load();
    const response = (url: string) => ({
      url,
      responseHeaders: { "Content-Type": "text/html", Server: "Apache/2.4.41 (Ubuntu)" },
      responseBody: "<p>hello</p>",
    });
    await mock.dispatch("traffic.on_response_received", response("https://app.test/a"));
    await mock.dispatch("traffic.on_response_received", response("https://app.test/b"));
    await mock.dispatch("traffic.on_response_received", response("https://api.app.test/c"));
    const found = mock.findings().filter((f) => f.types[0] === "fingerprint");
    expect(found).toHaveLength(1);
    expect(found[0].value).toBe("Server: Apache/2.4.41 (Ubuntu)");
    expect(found[0].hidden).toBe(false);
    expect(found[0].links.map((l) => l.url)).toEqual(["https://app.test/a", "https://api.app.test/c"]);
    expect(found[0].links[0].location).toBe("response_header");
    expect(found[0].notes.split("Web server banner")).toHaveLength(2); // written once
    expect(found[0].notes).toContain("ServerTokens Prod");
  });
});
