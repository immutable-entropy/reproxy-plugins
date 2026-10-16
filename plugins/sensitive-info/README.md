# sensitive-info

Reads every targeted request, response and WebSocket message and records
what shouldn't be travelling in the clear: credentials, keys and tokens,
password hashes, and personal data. Each hit becomes a finding whose value
is the thing itself, linked to the request it was seen in; the same value
found again adds a sighting rather than a second finding.

It only reads traffic. Nothing is held, changed or sent, and the scanning
happens after the message has been forwarded.

Values that are secrets in themselves are recorded **hidden**, so reProxy
keeps them masked until you click the eye beside the value. Personal data
that identifies rather than authenticates — an email address, a telephone
number, a date of birth — is left readable, because masking what you are
looking at helps nobody. Turn it off with **Hide secret values**.

## Where it looks

| Part | What is read |
|---|---|
| The URL's query string | A credential in a URL is a finding of its own: it reaches server logs, browser history and Referer headers. The notes say so. |
| Headers | `Authorization` and `Proxy-Authorization` of any scheme (Basic is decoded to the user name and password it hides), cookies, `X-Api-Key` and anything else named like a credential. |
| Bodies | Form, JSON, XML and multipart bodies, up to **Largest body scanned**. |
| WebSocket messages | Both directions, text messages only. |
| Response headers, for the stack | What the site runs on: see [fingerprint](#fingerprint). Request headers are the browser's, so they aren't read for this. |

Replayed traffic and an agent's sends come through the same hooks, so they
are scanned too. Requests can be turned off with **Scan requests**.

## Detectors

Every detector has an id, and every id belongs to a category — the finding
type it records. Both work in the **Detectors to run** and **Detectors to
skip** settings: `email` is one detector, `personal-data` is all of them in
that category.

### credential

`field_password`, `field_pin` (one-time and PIN codes), `field_username` (only
beside a credential, and only in a request), `url_credentials`
(`postgres://user:pass@host`), and the `auth_header` schemes that carry a
password: Basic, Digest, NTLM and Negotiate.

### secret-key

`field_api_key`, `private_key` (PEM, including the escaped form inside JSON),
`putty_key`, and the formats that name their issuer: `aws_access_key`,
`github_token`, `gitlab_token`, `slack_token`, `slack_webhook`,
`discord_webhook`, `stripe_key`, `google_api_key`, `google_oauth_secret`,
`firebase_server_key`, `anthropic_key`, `openai_key`, `npm_token`,
`pypi_token`, `sendgrid_key`, `mailgun_key`, `shopify_token`, `square_token`,
`digitalocean_token`, `telegram_bot_token`, `atlassian_token`,
`dropbox_token`, `figma_token`, `linear_key`, `postman_key`,
`new_relic_key`, `supabase_key`, `doppler_token`, `vault_token`,
`grafana_token`, `jfrog_token`, `azure_storage_key`.

### token

`jwt` (the claims are decoded into the finding's details, including
`jwt.header.alg`, so an `alg: none` token stands out), `auth_header`,
`auth_header_bare`, `field_token`, `field_session` (session identifiers and
CSRF tokens).

### hash

`bcrypt_hash`, `argon2_hash`, `crypt_hash`, `apr1_hash`, `phpass_hash`,
`framework_hash` (Django and friends), `ldap_hash`, `mysql_hash`,
`ntlm_pair`, `shadow_line`, `field_hash`, `field_salt`, and `hex_hash` —
which only the **Report bare hex hashes** setting turns on, because too much
of the web is 32 hex characters.

### personal-data

`email`, `phone`, `ssn` (checked against the numbers that can be issued),
`uk_nino`, `field_email`, `field_phone`, `field_dob`, `field_gov_id`
(passport, driving licence, tax and national identifiers).

### payment-data

`credit_card` and `field_card` (both checked with Luhn), `field_cvv`,
`iban` and `field_bank` (IBANs are checked with their mod-97 checksum).

### fingerprint

Response headers that tell an attacker what the site runs on. None is a
secret, so these findings are never hidden, and none is a vulnerability by
itself, but each saves an attacker work (a version to look up CVEs for, an
internal host to aim a server-side request forgery at), and the notes say
how to switch it off.

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

**Only report server and framework banners that name a version** drops
`Server: nginx` but keeps `Server: nginx/1.18.0`; the other detectors are
unaffected. Skip `fingerprint` to turn the lot off.

## What it won't say

A value is only reported when it survives a check: a card number must pass
Luhn, an IBAN its checksum, an SSN must be one that can exist, a generic
`api_key` must look random enough (**Minimum entropy for generic keys**), and
a masked or templated value (`****`, `{{token}}`, `your_api_key`) is never a
finding. Field names that only talk about a secret — `password_strength`,
`has_password`, `user_agent` — are ignored.

Weak real passwords are *not* ignored: `password=test` in a test
environment is a credential on the wire, and the point of the plugin.

Use **Values to ignore** for the ones you know about — a sample key an API's
documentation returns, the test account's password — and **Email domains to
ignore** for the addresses that aren't a person's.

## What it costs

The plugin reads every message of every targeted flow, and a plugin turn has
250 ms, so cost is part of correctness here.

`text.scan` runs RE2 in Go, which is linear in the input but has no literal
to jump between when a pattern is a large alternation. Measured on a 512 KiB
body, the pattern for named fields alone takes over half a second. So a
format with a literal in it (`AKIA`, `-----BEGIN`, `$2y$`, `password`) is
**anchored**: one `indexOf` over a lower-cased copy says whether the literal
is there at all — fifty of those cost about 7 ms over that same body — and
the patterns are run only on the windows of text around what they found. A
format with nothing to anchor on (an email address, a card number) has to be
looked for everywhere, so those patterns are small ones and are run over the
body up to **Largest body scanned for personal data**, which is lower.

A 512 KiB body with nothing in it takes about 80 ms; a login takes about 3.
`test/cost.test.ts` measures it, and is the thing to run after touching a
pattern.
