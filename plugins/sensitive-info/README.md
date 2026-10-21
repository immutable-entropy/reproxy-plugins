# sensitive-info

Reads every targeted request, response and WebSocket message — and every
file the work recovered — and records what shouldn't be there: credentials, keys and tokens,
password hashes, and highly sensitive personal data — payment cards, bank
and government identifiers, dates of birth. Each hit becomes a finding whose
value is the thing itself, linked to the request it was seen in; the same
value found again adds a sighting rather than a second finding.

It only reads traffic. Nothing is held, changed or sent, and the scanning
happens after the message has been forwarded.

Values that are secrets in themselves are recorded **hidden**, so reProxy
keeps them masked until you click the eye beside the value. A date of birth,
which identifies but doesn't authenticate, is left readable, because masking
what you are looking at helps nobody. Turn it off with **Hide secret values**.

> This is the highly sensitive half of what was once a single plugin.
> Contact details and the external footprint — emails, telephone numbers,
> postal addresses, social-media accounts, source-code repositories — are now
> the **footprint** plugin's; what a response's headers give away about the
> stack is the **stack-disclosure** plugin's.

## Where it looks

| Part | What is read |
|---|---|
| The URL's query string | A credential in a URL is a finding of its own: it reaches server logs, browser history and Referer headers. The notes say so. |
| Headers | Only what a format proves to be a secret: a provider's key, a password hash, a password or card number in clear, an HTTP Basic credential (decoded to the user name and password it hides). A token or session identifier is **not** — see "Your own session", below. |
| Bodies | Form, JSON, XML and multipart bodies, up to **Largest body scanned**. |
| WebSocket messages | Both directions, text messages only. |
| Recovered files | The files another plugin recovered into the engagement — the application's own source, un-webpacked from an exposed map — read with the same detectors as a body, and the finding links to the file. Turn it off with **Scan the files the work recovers**. |

Replayed traffic and an agent's sends come through the same hooks, so they
are scanned too. Requests can be turned off with **Scan requests**.

## Your own session

This plugin runs beside somebody driving the application in a browser, not
beside an attacker reading the wire. Every `Cookie`, `Set-Cookie`,
`Authorization` and `X-CSRF-Token` that passes therefore carries a
credential that tester already holds, and reporting each one buries the
findings that matter under their own session.

So in a **header**, a value is only reported when something other than its
field name shows it to be a secret: a provider's key format
(`AKIA…`, `sk_live_…`), a password hash, a password or card number in
clear, an HTTP Basic credential. A token, a session identifier or a
key-shaped value under a credential-sounding header name is not. `Bearer`,
`Digest`, `NTLM` and `Negotiate` credentials are not reported either: the
first is the session, and the rest change with every nonce.

The same value in a query string, a body or a recovered file is still
reported in full, because there it is the application putting a secret
somewhere it does not belong. **Report tokens and session identifiers in
headers** turns the whole policy off, for reading traffic that isn't your
own.

## Detectors

Every detector has an id, and every id belongs to a category — the finding
type it records. Both work in the **Detectors to run** and **Detectors to
skip** settings: `ssn` is one detector, `personal-data` is all of them in
that category.

### credential

`field_password`, `field_pin` (one-time and PIN codes), `field_username` (only
beside a credential, and only in a request), `url_credentials`
(`postgres://user:pass@host`), and `auth_header` — HTTP Basic, decoded to
the user name and password it carries.

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
`jwt.header.alg`, so an `alg: none` token stands out), `field_token`,
`field_session` (session identifiers and CSRF tokens). These, with
`field_api_key`, `field_username` and `hex_hash`, are the detectors a
header is not read for; see "Your own session".

### hash

`bcrypt_hash`, `argon2_hash`, `crypt_hash`, `apr1_hash`, `phpass_hash`,
`framework_hash` (Django and friends), `ldap_hash`, `mysql_hash`,
`ntlm_pair`, `shadow_line`, `field_hash`, `field_salt`, and `hex_hash` —
which only the **Report bare hex hashes** setting turns on, because too much
of the web is 32 hex characters.

### personal-data

`ssn` (checked against the numbers that can be issued), `uk_nino`,
`field_dob`, `field_gov_id` (passport, driving licence, tax and national
identifiers). Email addresses and telephone numbers are the **footprint**
plugin's, not this one's.

### payment-data

`credit_card` and `field_card` (both checked with Luhn), `field_cvv`,
`iban` and `field_bank` (IBANs are checked with their mod-97 checksum).

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
documentation returns, the test account's password.

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
format with nothing to anchor on (a card number, an SSN) has to be looked
for everywhere, so those patterns are small ones and are run over the body
up to **Largest body scanned for personal data**, which is lower.

A 512 KiB body with nothing in it takes about 80 ms; a login takes about 3.
`test/cost.test.ts` measures it, and is the thing to run after touching a
pattern.
