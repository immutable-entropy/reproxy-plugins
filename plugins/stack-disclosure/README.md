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
not the target, so they say nothing about it. Nothing is held, changed or
sent, and the reading happens after the response has been forwarded.

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

## Settings

| Setting | |
|---|---|
| **Only report banners that name a version** | Drops `Server: nginx` but keeps `Server: nginx/1.18.0`, and likewise for `tech_header` and `proxy_banner`. The other detectors are unaffected. |
| **Detectors to skip** | Detector ids never to report: `server_banner`, `tech_header`, `app_version`, `proxy_banner`, `internal_host`, `internal_address`, `bigip_cookie`, `stack_cookie`, `debug_header`. |
| **Most findings from one response** | A response whose headers trip more detectors than this is stopped at the cap. |

## What it costs

A head is small, so this is plain string work in the plugin — no body is
read and no `text.scan` is needed. The scan happens after the response has
been forwarded, so it never slows traffic.
