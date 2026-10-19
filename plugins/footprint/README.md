# footprint

Maps an organisation's external footprint from its own traffic: the contact
details it publishes, the social-media accounts and source-code repositories
it links to, the cloud storage buckets, package-registry entries and
third-party services it uses, and the API and documentation endpoints it
exposes. Each is recorded as a finding linked to the response it was seen in;
the same value found again adds a sighting rather than a second finding.

It only reads responses. Nothing is held, changed or sent, and the reading
happens after the response has been forwarded. None of what it records is a
secret — these findings identify, they don't authenticate — so none is
hidden.

> This plugin is the footprint part of what was once the **sensitive-info**
> plugin. Secrets and highly sensitive personal data (payment cards,
> government identifiers, dates of birth) stay with **sensitive-info**;
> stack-disclosure headers are the **stack-disclosure** plugin's.

## How it reads a response

The http(s) URLs a response refers to are extracted in Go (`text.urls`) and
each is classified. Everything that isn't an ordinary link — third-party
service ids, `mailto:`/`tel:` links, `s3://` URIs, structured postal
addresses, and email and telephone text — is found by literal-anchored
patterns. Emails and telephone numbers in the body text have no literal to
anchor on, so they are read over a bounded slice (**Largest body scanned for
emails and phone numbers**); everything else covers the whole body.

### Context matters for social and source links

A social-media account or a repository in the site's `<header>`, `<footer>`
or `<nav>`, or carrying `rel="me"`, or inside a container that announces
itself as social links, is almost certainly the organisation's own. The same
link deep in an article or a comment may be a third party's or a visitor's.
The finding's notes and its `source` field say which, and its `context` field
names the region the link sat in.

Links to **individual** posts, videos and repository files are left out by
default — only accounts and repositories (a profile, an org or repo page) are
recorded. Turn **Include links to individual posts and files** on to record
them too.

## Detectors

Every detector has an id, and every id belongs to a category (the finding
type it records). Both work in **Detectors to skip**: `github` is one
detector, `source-repo` is all of them in that category.

### contact

`email` (in the body text) and `email_mailto` (a `mailto:` link), `phone`
(an international `+…` number in the text) and `phone_tel` (a `tel:` link),
and `postal_address` (a street address in the page's schema.org structured
data). Addresses that aren't a person's or an organisation's — an ignored
domain, an asset name like `logo@2x.png` — are dropped, and a number that
can't be a telephone number is too.

### social-account

`facebook`, `twitter` (X), `linkedin`, `instagram`, `youtube`, `tiktok`,
`telegram`, `whatsapp`, `reddit`, `mastodon`, `bluesky`, `threads`,
`discord`, `vimeo`, `twitch`, `medium`, `pinterest`, `tumblr`, `snapchat`,
`vk`, `xing`. The platform's own share, intent and search links are not
accounts and are skipped.

### source-repo

`github`, `gitlab`, `bitbucket`, `codeberg`, `gitea`, `sourceforge`,
`azure_devops`, `gitee`, `sourcehut`, `launchpad`. An owner page and an
owner/repo page are recorded; the platform's own pages (features, login,
marketplace…) are skipped.

### cloud-storage

`bucket` — AWS S3 (virtual-hosted or path style), Google Cloud Storage,
Azure Blob Storage, Cloudflare R2, DigitalOcean Spaces, Alibaba OSS — and
`s3_uri` for an `s3://` URI in the body.

### package

`npm` (including scoped `@scope/name` packages), `pypi`, `rubygems`,
`packagist`, `crates` (crates.io), `nuget`, `dockerhub`, `maven`, and `ghcr`
(GitHub Container Registry images).

### service-id

`ga4` and `ua` (Google Analytics), `gtm` (Google Tag Manager), `sentry_dsn`
(a public Sentry DSN), `stripe_pk` (a Stripe publishable key — public by
design, but it names the account), `fb_pixel` (a Facebook Pixel id),
`segment_key` (a Segment write key), `intercom_app` (an Intercom app id).

### api-endpoint

`graphql` (and GraphiQL), `openapi` (an OpenAPI/Swagger definition, `/api-docs`,
`/v2/api-docs`), `swagger_ui` (Swagger UI, ReDoc, RapiDoc), `graphql_playground`,
and `postman` (a Postman documentation link).

## Settings

| Setting | |
|---|---|
| **Detectors to skip** | Detector ids or whole categories never to report. |
| **Include links to individual posts and files** | Off: only accounts and repositories. On: content links too, which is far noisier. |
| **Most findings from one response** | A page that links out dozens of times is stopped at the cap. |
| **Largest body scanned** | Bodies bigger than this are left alone. |
| **Largest body scanned for emails and phone numbers** | The lower cap for the two patterns that read the body itself. |
| **Email domains to ignore** | Addresses on these domains (and their subdomains) are never reported. |

## What it costs

Link extraction runs in Go, and every service-identifier pattern is anchored
on a literal that an `indexOf` over a lower-cased copy of the body checks for
first, so a body that can't hold a thing never has its pattern run. Only the
email and telephone patterns read the body itself, and only up to their own
cap. A 512 KiB body with nothing in it takes a few milliseconds.
`test/cost.test.ts` measures it, and is the thing to run after touching a
pattern.
