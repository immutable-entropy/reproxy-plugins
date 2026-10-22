# stack-disclosure

Reads the response headers of every targeted flow for what they give away
about the stack the site runs on: the web server and its version, the
language, framework or CMS, the deployed build, internal host names and
private addresses, framework session cookies, and debugging aids left
switched on.

None of it is a secret, and none is a vulnerability by itself, so these
findings are never hidden — but each saves an attacker work (a version to
look up CVEs for, an internal host to aim a server-side request forgery at),
and the notes say how to switch it off. Each is recorded as a finding linked
to the request it was seen in.

It only reads response headers. A request's headers come from the browser,
not the target, so they say nothing about it. Reading is passive: nothing is
held or changed, and it happens after the response has been forwarded. The
one part that reaches out is the optional vulnerability check below, which is
off by default.

> This plugin is the stack-disclosure part of what was once the
> **sensitive-info** plugin.

## Detectors

| Detector | What it reports |
|---|---|
| `server_banner` | `Server`, with or without a version. |
| `tech_header` | `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, `X-Jenkins`, `X-OWA-Version`, `Liferay-Portal`, `MicrosoftSharePointTeamServices` and the like; and headers whose presence names the product (`X-Drupal-Cache` → Drupal, `X-Runtime` → probably Rails, `X-Nextjs-Cache` → Next.js). |
| `app_version` | The deployed build: `X-Version`, `X-Build`, `X-Revision`, `X-Git-Commit` and friends, and Spring Boot's `X-Application-Context`. |
| `proxy_banner` | A `Via` that names its software, and gateways that show by a header of their own (Varnish, Kong, Envoy, Squid, Fastly). |
| `internal_host` | Headers naming the back-end node that answered: `X-Backend-Server`, `X-Served-By`, `X-Upstream`, Exchange's `X-FEServer`/`X-BEServer`/`X-CalculatedBETarget`, and others. |
| `internal_address` | A private, loopback, link-local or carrier-grade NAT IPv4 address in any response header (a `Location` pointing inside, an echoed `X-Forwarded-For`). |
| `bigip_cookie` | F5 BIG-IP's `BIGipServer<pool>` cookie, decoded to the internal address and port of the pool member when it isn't encrypted. |
| `stack_cookie` | Session cookies whose default names give the framework away: `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `laravel_session`, `connect.sid`, Drupal's `SESS…` and others. The cookie's value is never recorded here. |
| `debug_header` | Debugging aids left on: Symfony's profiler (`X-Debug-Token`), Laravel Debugbar and Clockwork, ChromeLogger, Xdebug. |

A finding's value is the header as sent (`Server: Apache/2.4.41 (Ubuntu)`),
or the product when the header's value changes from response to response
(`Drupal (X-Drupal-Cache header)`, `Symfony profiler (X-Debug-Token header)`).
Header names are written the usual way whatever the protocol, so HTTP/2's
`server` and HTTP/1.1's `Server` make one finding. These headers are on every
response, so each disclosure is recorded once per host: one finding, with a
sighting for every host that sends it.

## Looking disclosed versions up for vulnerabilities

A version banner is only worth finding because it leads somewhere — "look up
the CVEs for Apache 2.4.41". With **Look disclosed versions up for known
vulnerabilities** turned on (off by default, because it sends requests), the
plugin takes that step itself. When a banner names a **full version**
(`major.minor.patch`, e.g. `Apache/2.4.41`, `Server: BigIP 16.1.0`) of a
product it recognises, it looks the version up and records the known
vulnerabilities as findings, each graded by its CVSS score.

Two sources are used, because neither alone fits every banner:

- **NVD** (the NIST National Vulnerability Database) is queried by the
  product's CPE at the disclosed version, so the CVEs it returns are the ones
  that actually affect that version, each with a **CVSS base score** that sets
  the finding's criticality (Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 4.0, else
  Low — each a finding type of its own colour). This is sent to
  `services.nvd.nist.gov`. A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key),
  set as the plugin's secret setting, raises the rate limit from 5 to 50
  requests per 30 seconds; without one the lookups simply run slower.
- **CISA KEV** (the Known Exploited Vulnerabilities catalog, from
  `cisa.gov`) says which vulnerabilities are being **exploited in the wild** —
  the signal that turns a CVE into "patch this now" in a report. Each NVD CVE
  is cross-referenced against it, and the ones listed are flagged with the
  date CISA added them and their remediation due date. KEV also carries
  products that NVD can't match by version (F5 BIG-IP, Atlassian Confluence);
  for those, the finding lists the product's known-exploited CVEs and says to
  confirm whether the running version is affected, since KEV records no
  versions.

### What a vulnerability finding records

The CVE and the product version (`CVE-2023-46747 in nginx 1.18.0`), its CVSS
score and vector, the CWE, the publication date, whether it is in CISA KEV,
and links back to the **NVD** detail page and the **CISA KEV** catalog — enough
to drop into a report. The notes name the remediation (upgrade past the
affected version) and the caveat that a banner shows the version, not that the
application is exploitable: confirm it uses the affected feature first.

Only the product name and version are ever sent — never a target's address.
Every lookup is recorded in the Traffic list, so the whole run is auditable,
and answers are kept for a day, so a version (or the 1.8 MiB KEV feed) is
fetched once however often it is seen.

### A note on coverage

NVD is matched by a curated product→CPE map (the CPE vendor is not always
obvious — nginx's is F5's), so only recognised products are looked up: a
guessed CPE finds nothing or the wrong thing. Products outside that map, and
appliances NVD splits across many CPE products, fall to the KEV product-level
match where they are covered there. Language-library versions are out of
scope here — the **js-libraries** plugin looks those up on osv.dev.

## Settings

| Setting | |
|---|---|
| **Only report banners that name a version** | Drops `Server: nginx` but keeps `Server: nginx/1.18.0`, and likewise for `tech_header` and `proxy_banner`. The other detectors are unaffected. |
| **Detectors to skip** | Detector ids never to report: `server_banner`, `tech_header`, `app_version`, `proxy_banner`, `internal_host`, `internal_address`, `bigip_cookie`, `stack_cookie`, `debug_header`. |
| **Most findings from one response** | A response whose headers trip more detectors than this is stopped at the cap. |
| **Look disclosed versions up for known vulnerabilities** | The active check above. Off by default; on, it sends requests to NVD and CISA. |
| **NVD API key** | Optional secret. A free key raises NVD's rate limit (50 vs 5 requests per 30 s). |
| **Query the NVD API** / **Use CISA's KEV catalog** | Each source can be turned off on its own. |
| **Only look up a full version** | On (default): only a complete `major.minor.patch` version is looked up, since a two-part release line like `1.18` can't be matched to a CVE reliably. |
| **Lowest CVSS score to report** | A CVE below this base score is dropped (7 reports only High and Critical). KEV product matches, which carry no score, are unaffected. |
| **Most CVEs per version** | The cap on findings for one disclosed version, most severe first. |

## What it costs

A head is small, so this is plain string work in the plugin — no body is
read and no `text.scan` is needed. The scan happens after the response has
been forwarded, so it never slows traffic.

The vulnerability check adds no cost to a response's own turn: its network
calls are awaited (the wait doesn't count against the CPU budget), paced to
NVD's rate limit, and bounded by the daily cache. Parsing a large NVD answer
and reducing the full KEV feed both stay well inside the turn budget, proven
by `test/cost.test.ts`.
