# reproxy-plugins: guidance for Claude sessions

This repository holds the plugins for **reProxy**, an intercepting proxy for
testing web apps (the app is `github.com/immutable-entropy/reproxy`,
checked out in the devcontainer at `/workspaces/reproxy`). Every plugin
reProxy runs comes from a repository like this one: **nothing is bundled
into the app**. This is the default repository the app's Plugins window
browses, so a plugin merged here is one any user can install.

`README.md` is the full reference for plugin authors (manifest fields, every
hook, match filters, the SDK, the test harness). This file is the working
guide: how plugins fit into reProxy, the rules a plugin must keep, and the
workflow for writing one. When the two disagree, the SDK and manifest code
in the app are the truth (see "Where the truth is" below). Fix whichever
document is wrong.

## How a plugin reaches a user

1. The user opens the **Plugins** window (the puzzle piece above the cog in
   reProxy's navigation bar) and, under **Repositories**, browses this
   repo.
2. reProxy lists every directory holding a `plugin.json` (at the repo root,
   in a top-level directory, or under `src/` or `plugins/`; here it's
   `plugins/<name>/`).
3. Installing downloads only `.ts`, `.js`, `.mjs`, `.cjs`, `.json`, `.md`
   and `.txt` files. It skips `*.test.ts`, anything under a `test/`
   directory, and `node_modules/`. The limits are 200 files, 2 MiB per file
   and 16 MiB in total. The download is validated (the manifest parses,
   every function a target names is exported) and copied into the user's
   data directory (`~/.reproxy/plugins/<name>/`).
4. It is installed **disabled**, whatever `status` says, so downloaded code
   never runs until the user has looked at it and enabled it. `status` only
   decides the default for a plugin put in the folder by hand.

So a plugin must work from its downloaded files alone. Anything it needs at
run time is a `.ts`/`.js`/`.json` file inside its own directory.

## Repository layout

```
README.md                  the authoring reference (keep it current)
CLAUDE.md                  this file
plugins/
  <name>/                  one directory per plugin; the name equals plugin.json's "name"
    plugin.json            the manifest
    main.ts                the entry point; exports every function plugin.json names
    src/*.ts               the logic, as plain functions that can be unit-tested
    test/*.test.ts         tests, run by `reproxy plugins test`; never installed
```

The current plugins are good models. Read the closest one before writing a
new one:

| Plugin | Shows how to |
|---|---|
| `wordpress` | watch the **Entity Explorer** (`url.*` hooks) instead of traffic, read the flows behind a URL, keep per-run state that `plugin.on_load` resets, record findings that merge, and keep an opt-in active scan to one request per part per engagement by writing what was asked — and what it answered, including nothing — to `storage.engagement` |
| `sensitive-info` | scan a message's headers, query string and body (and WebSocket messages) with `text.scan` (RE2 in Go), keep a big body affordable by gating patterns behind a plain text search, record a secret `hidden`, use tight `content_types` filters, use list, number and boolean settings, and redact values |
| `footprint` | pull the links out of a response in Go (`text.urls`) and classify each in TypeScript, read HTML structure by hand (is a link in the `<header>`/`<footer>`/`<nav>`, or `rel="me"`?) without a DOM, gate literal-anchored patterns behind `indexOf` to stay cheap, and record findings that identify rather than authenticate (never `hidden`); keep `test/cost.test.ts` to prove the cost holds |
| `stack-disclosure` | act on response headers alone with plain string work (no `text.scan`, no body read), record a finding once per host (dedupe on value+host) so it gains one sighting per host rather than per response, and keep `plugin.on_load` to reset that per-run set |
| `saml-inspector` | decode a protocol (base64 + DEFLATE + XML) in pure TypeScript and grade what it finds |
| `precon` | be driven from the command line rather than by traffic (`commands`, `reproxy precon <action>`, no traffic or entity hooks), with the lookup logic kept as plain functions under `src/` that the command handlers in `main.ts` call; merge two services' answers into one record and parse a binary format (a certificate's SANs) in TypeScript (`src/ssl`), and read a third-party API's reply defensively (`src/dns`) |
| `js-libraries` | watch responses of one kind (`content_types`) on the targets and, with a `hosts` list and the Referer, the third-party hosts a target's pages load from; gate `text.scan` patterns behind `indexOf` needles; write notes that stay the same on every sighting so findings merge cleanly; look results up in an outside API once and keep the answers in `storage` with an expiry |
| `spa-recon` | detect a framework (Vue/Nuxt, React/Next, Svelte/SvelteKit, Angular) and build from the HTML and the bundles it loads; send requests of the plugin's own (`http.send`, through the upstream chain, `record: true`) to fetch build artefacts only on in-scope hosts; parse a large JSON source map and a build manifest defensively; confirm a fact from a second source (the map) when the first (the HTML) is inconclusive; remember probed origins and fetched files in `storage.engagement` so active work is done once |
| `param-miner` | be driven only by a user action (`actions`, right-click → "Param Miner", no traffic or entity hooks, so it is never automatic), send many `http.send` probes to the chosen request's own host bounded by a request cap and pacing, learn a per-request baseline and judge a guess against the target's own noise, bisect a reacting batch and confirm each candidate on its own before recording it (so an unconfirmed guess is never a finding), and add a unique cache-buster to every probe so active testing behind a CDN never shares a cache key with a real user; keeps the detection logic pure under `src/` and `test/cost.test.ts` to prove the response scan stays cheap |
| `laravel` | decide a host runs a given framework before saying anything about it (strong and weak evidence from `src/detect.ts`, accumulated across responses), read a framework's debug error page for the configuration and secrets it prints, confirm an exposed dev tool from what it served rather than from its path (a 200 on `/telescope` is as likely to be a single-page app's route), split the work over three targets — a head-only check on every response, a body read only where an error page could be, and a `paths` filter for the exposures — so each `match` stays tight, and keep `test/cost.test.ts` to prove the body read holds; keep active work to once per host for good by writing the record to `storage.engagement` before the requests go out and reading it back in place of re-detecting the host, with the result left on the entity's `kv` |

## Core or plugin?

reProxy's core (Go) is intercepting, editing and replaying traffic, and
every request pays for core code, so core stays small and fast. Everything
else, especially automated QA and security testing, is meant to be built
**as plugins**. If a feature could be done by watching traffic, the
Explorer or findings, or by answering held messages, it belongs here. If it truly can't
be done without a new hook or SDK function, that's a change to the app
(`/workspaces/reproxy`, `internal/plugin`). Make it there first, keep the
SDK and README in step, and say so plainly.

Finding URLs, hosts and domains in traffic is core, not a plugin: the app
reads every response for the URLs it refers to, puts them in the **Entity
Explorer** ("the Explorer"), and lists hosts no target covers under Targets →
Related. Don't write a plugin that re-extracts links; use the entity hooks to
act on what core found.

The Explorer holds typed **entities**: a `domain` (registrable domain,
`example.com`) holds name `host`s (a DNS name or IP address on its own,
key `//api.example.com`, which DNS facts belong to; an IP's is a root), which
hold origin `host`s (`https://api.example.com:8443`), which hold
`url`s (templated: `/users/12` → `/users/{id}`). Each has a `key`, its
`parent`'s key, `visited` (false while only discovered), and a `kv`
string store any plugin can write (`entities.set`/`unset`); use it to leave
per-entity notes for other plugins rather than a private map. Each type has
`on_created`/`_updated`/`_deleted` hooks (`url.*`, `host.*`, `domain.*`),
and `entity.*` fires for all three (narrow it with `match.types`).
`on_created`/`_updated` only run for entities in a target unless the user
opts in to all of them (Settings → Targets); don't rely on hearing about
related hosts.

Files the work **recovers** are core too (`internal/files`), for the same
reason: a plugin produces the bytes — core writes them, since a plugin has no
filesystem — but a recovered file is something *other* plugins act on. Hand a
recovery to `files.addAll` (or one file to `files.add`) and core records it,
puts it under `<engagement>/recovered/`, and calls `file.on_created` on
whoever targets it; a scanner then reads it with `files.read` using the code
it already has for response bodies. Don't keep recovered text in a variable
or in `storage` and scan it yourself: that hides it from the other plugins,
from the user's Files section, from `reproxy files …` and from their agents.
Recovering a path with bytes it already holds changes nothing and raises no
event, so a recovery is safe to run twice. A recovery of thousands of files
will overrun a plugin's queue; that is what `file.on_batch_complete` and
`files.list({ batch })` are for.

## The rules a plugin must keep

These follow from how core runs plugins. A plugin that breaks them costs
every user's traffic, or gets stopped.

- **Filter in `match`, not in code.** `match` runs in Go before anything
  reaches the plugin. An event it turns away costs nothing; one it accepts
  is copied onto the plugin's queue (1024 events, then dropped and counted).
  Always set `scope` (usually `"in_scope"`) and narrow by `content_types`,
  `paths`, `hosts`, `methods` or `status` wherever the plugin only cares
  about some traffic. A body scanner without a `content_types` filter runs
  on every image and font.
- **Prefer observe hooks.** `traffic.*`, the entity hooks, `finding.*` and the
  rest are asynchronous: they never slow the traffic. Only the intercept
  hooks (`intercept.on_request_pending`, `intercept.on_response_pending`,
  `websocket.on_message_pending`) make the proxy wait, and only for what
  interception (or the plugin's own `hold`) holds. Use them only to change
  or drop traffic.
- **`hold: true` is expensive.** It makes the proxy buffer and wait on every
  message `match` accepts, even with interception off. Use it only for
  rewriting plugins (header injectors, response rewriters), with the
  tightest `match` that works, and answer fast: the default timeout is 2 s,
  and a timeout counts as a pass.
- **Watch the Explorer rather than the traffic when you can.** The Explorer
  has one entry per URL (and per host and domain), so `url.on_created` runs
  once per new thing seen, not once per request (see `wordpress`). Narrow
  `url.on_updated` with `paths`, because it fires on every new hit (and
  `host.on_updated`/`domain.on_updated` fire on every hit beneath them).
- **Stay passive by default.** A plugin that only reads what the traffic
  already carried can be enabled safely. One that sends requests
  (`http.send`) is active testing: say so in its description, put the
  sending behind a setting where it makes sense, and keep it to the hosts
  the targets cover (`targets.match(url)`). Plugins *can* reach any host, but
  testing off-target hosts is a decision for the user, not the plugin.
- **Active work happens once.** A request a plugin sends by itself is sent
  at somebody's server, so the same test must not be repeated every time
  the tester reloads the plugin, restarts reProxy or walks through the site
  again. A module-level `Set` only covers the run; what has been asked goes
  in `storage.engagement`, keyed by whatever the test is *of* — the host
  (`laravel`), the plugin or theme (`wordpress`), the origin or the file
  (`spa-recon`) — and is consulted before anything is sent. Write the
  record **before** the first request rather than after the last, so a
  check cut short by a reload still counts as done; that is the safer way
  round when the cost of being wrong is somebody else's server. Remember a
  negative answer too (a readme.txt that isn't there will not be there
  next week), bound what you keep so the megabyte of storage can't
  overflow, and read it back instead of working the target out from
  scratch. The record belongs to the engagement, so reset the in-memory
  copy of it in both `plugin.on_load` and `engagement.on_opened`. A
  lookup in a third-party database (`js-libraries` asking osv.dev) is a
  different matter: cache it in `storage` with an expiry, since the answer
  changes over time.
- **Heavy text work goes to Go.** goja is many times slower than V8. Scan
  bodies with `text.scan` (RE2: no backreferences or lookaround, repeats up
  to 1000, linear time) and extract URLs with `text.urls`. Don't loop a JS
  regex over megabytes. Skip bodies larger than you need (`wordpress` caps
  at 4 MiB).
- **A pattern with no leading literal is expensive.** `text.scan` runs each
  pattern it is given in a pass of its own, so compose alternatives into
  one; but Go's regexp only skips ahead with a text search when a pattern
  starts with a single literal, and submatches cost more still. A 60-way
  name alternation over a 512 KiB body takes more than half a second, while
  `AKIA[0-9A-Z]{16}` takes under a millisecond. Gate such a pattern with
  `indexOf` on a lower-cased copy first (about 7 ms for fifty needles over
  512 KiB) and run it only on slices around the hits — `sensitive-info`
  does this, and keeps `test/cost.test.ts` to prove it still holds.
- **Every turn has 250 ms.** A hook call, a timer callback, or the code
  between two `await`s is interrupted after 250 ms of CPU (waiting on the
  network doesn't count). A plugin that fails 5 times in a minute is
  stopped for the session. Break up big work, and never busy-wait.
- **Findings explain themselves.** `findings.record` requires `notes`: say
  what was found, where, and why it matters, in plain language a tester can
  act on. Pass `hidden: true` when the value is a secret in itself (a
  password, a key, a token, a card number, a national identifier): reProxy
  then masks it on screen until the user clicks the eye beside it. Data that
  is sensitive but not secret — an email address, a telephone number — is
  left readable. The `value` is the identity: findings with the same value merge
  into one with another sighting. So choose a value that is stable and
  specific (`"akismet (blog.test)"`, the token itself), and link the flow
  (`flowId`, `location`, `detail`). Declare the plugin's finding types in
  `finding_types`, with a distinct colour.
- **Claim no more than the evidence shows.** Say "probably" or "unknown"
  when that is the truth (see how `wordpress` handles a `?ver=` that is
  really the core version). A false finding wastes a tester's time.
- **Secrets are settings of type `secret`.** They never have a default and
  never go in `plugin.json` or the repo. Read them with `settings.get`.
  Never log a secret, and redact credentials you record when the full value
  isn't needed (see `sensitive-info/src/redact.ts`).
- **No outside code.** A plugin can import its own files (relative paths),
  `.json` files, and the SDK (`reproxy`, plus `reproxy/testing` in tests),
  and nothing else: no npm packages, Node built-ins, `fetch`, `require`,
  `process`, filesystem or DOM. Vendor small helpers under `src/` (keep their
  licence notice), and treat a vendored file as a pinned dependency: copy it
  from a tagged release at least 14 days old (the same soak period core
  holds its Go modules to), never minified, and put a header comment naming
  the upstream URL, the exact version or commit, the date it was copied and
  the SHA-256 of the upstream file. Read all of it before committing, and
  never edit it in place: updating means copying a newer (soaked) release
  and updating the header. Prefer writing the helper yourself. Unicode property escapes (`\p{L}`) don't work in JS
  regexes; use `text.scan`.
- **Your own traffic is skipped.** Hooks don't see the plugin's own sends
  unless a target sets `self` (never allowed on intercept hooks). A send
  made while handling your own traffic counts a level deeper, and past
  depth 3 it fails with `E_RECURSION`. Don't design around feeding yourself.
- **State is per run.** Module-level variables last until the plugin is
  reloaded. Reset them in a `plugin.on_load` function (tests call it in
  `beforeEach`). Use `storage` (1 MiB, JSON) only for what must survive a
  restart, and `storage.engagement` for what belongs to the engagement.

## Writing a plugin: the workflow

1. **Pick a name**: 2 to 64 lower-case letters, digits and dashes. Create
   `plugins/<name>/` with that exact name.
2. **Write `plugin.json`**, starting from the closest existing plugin:
   - `"version": "1.0-1"`, `"sdk": "1"`, `"author": { "name": "reProxy" }`
     for first-party plugins (no personal names or emails).
   - `"status": "disabled"`, unless the plugin is passive and cheap enough
     to run on everything it matches.
   - a one- or two-sentence `description` saying what it does, and whether
     it sends requests.
   - `finding_types` if it records findings.
   - `targets`, with tight `match` filters.
   - `settings` for anything a user might reasonably want to change.

   Unknown fields are refused, so a typo is an error, not a no-op.
3. **Put the logic in `src/` as plain functions**: given text or a parsed
   value, return what was found. Keep SDK calls (`findings.record`,
   `entities.addUrl`, `http.send`) in `main.ts`'s hook functions, which glue
   the events to that logic. Then the logic can be tested with no
   fixtures at all.
4. **Write `main.ts`.** Start it with a comment saying what the plugin does,
   what it watches, and why it is built that way (see the top of
   `wordpress/main.ts`). Type each hook's argument with `Hooks["<hook>"]`
   (or `PendingEvent` / `WebSocketPendingEvent` for intercept hooks).
   Export every function a target names.
5. **Write tests** in `test/`:
   - unit tests for `src/` (`<module>.test.ts`);
   - `hooks.test.ts`, which drives the hook functions through
     `mock.dispatch`, so the manifest's `match` filters are exercised as core
     would run them. Assert what was recorded with `mock.findings()` and
     `mock.entities()` (`mock.entity(flow)` puts a flow in the Explorer and
     returns its URL), and what was sent with `mock.sent()` (outbound
     requests are never really sent; script them with `mock.respond`).
   - Cover what the filter must turn away as well as what it accepts:
     `mock.dispatch` resolves with how many functions ran, so `toBe(0)`
     proves a filter works.
6. **Validate and test** (see the commands below) until both are clean.
7. **Update `README.md`** if the plugin should be listed or the reference
   changed.

Changing an existing plugin: bump `version` (`1.0-1` → `1.0-2` for a fix,
`1.1` for a feature), keep its tests passing and add one for the change.
Renaming a setting key orphans what users saved under the old key, so
avoid it.

## Commands

The `reproxy` binary carries the plugin tools. None of them start the app or
need a display. From `/workspaces/reproxy`, `make build` writes
`bin/reproxy`; `go run ./cmd/reproxy plugins ...` works too.

```sh
R=/workspaces/reproxy/bin/reproxy
$R plugins validate plugins/<name>          # manifest + exported functions
$R plugins test plugins/<name>              # every *.test.ts
$R plugins test -v -run 'JWT' plugins/<name>  # one test, with the plugin's log
$R plugins types plugins/<name>             # SDK types + tsconfig.json for an editor

# everything, before committing:
for d in plugins/*/; do $R plugins validate "$d" && $R plugins test "$d" || break; done
```

Tests run in the same goja runtime as the app, against a throwaway
engagement with real stores: findings really merge, URLs really
template. Each test has 5 s, and everything is reset before each one.

`plugins types` writes `.reproxy/` and `tsconfig.json` into the plugin's
directory. TypeScript types are only stripped when a plugin loads, never
checked, so this is how you get type errors in an editor. Don't commit
those files (`.gitignore` covers them).

## Continuous integration

`.github/workflows/ci.yml` runs on every push. It builds the Qt-free command
line from the app repository (`make build-headless` there) and runs
`reproxy plugins validate` and `reproxy plugins test` over every plugin, and
it audits any npm modules a plugin imports — of which there are none, so that
job detects their absence and stops; it activates itself if a `package.json`
is ever added (which the "No outside code" rule means shouldn't happen).

Running the tests needs the app repository, which is private, so CI needs one
secret: `REPROXY_APP_TOKEN`, a token that can read `immutable-entropy/reproxy`
(a fine-grained PAT with Contents: Read, or a deploy key). It builds the
runner from that repository's `main` by default; set the `REPROXY_APP_REF`
variable to build from another ref. The headless build must be present on
whichever ref is used.

To try a plugin in the running app, copy (or symlink) its directory into
`~/.reproxy/plugins/` and open the Plugins window. It looks for plugins
again each time that section is shown, and **Reload** picks up edits. The
plugin's log, call counts and errors are shown there. For a headless
check, see the Xvfb notes in `/workspaces/reproxy/CLAUDE.md`.

## Where the truth is

The README describes the SDK; the app's code defines it. When in doubt, read:

| What | Where (in `/workspaces/reproxy`) |
|---|---|
| The SDK: every function, model and event type | `internal/plugin/sdk/index.ts` |
| The test harness (`mock`, `expect`) | `internal/plugin/sdk/testing.ts` |
| The runtime's globals | `internal/plugin/sdk/globals.d.ts` |
| The hook catalog, and which hooks are lifecycle, observe or decide | `internal/plugin/manifest/hooks.go` |
| Manifest validation | `internal/plugin/manifest/manifest.go` |
| Match filters and which fields apply to which hooks | `internal/plugin/manifest/match.go` |
| What is downloaded on install | `internal/plugin/registry/registry.go` (`keepInstallable`) |
| How plugins are bundled and run (imports, the time budget) | `internal/plugin/jsrt/` |

A quick reminder of what's there (the README has the details):

- **Hooks.** Lifecycle hooks: `plugin.on_load`, `on_unload`,
  `on_status_change`, `on_settings_change`. Observe hooks: `traffic.*`
  (`on_request_received`, `on_request_forwarded`, `on_response_received`,
  `on_response_forwarded`, `on_flow_complete`, `on_flow_failed`,
  `on_flow_dropped`), `intercept.on_released`, `replay.on_sent`,
  `finding.on_finding_created`/`_updated`/`_removed`, `target.on_changed`,
  `engagement.on_opened`/`_closed`, `url.*`, `host.*`, `domain.*` and
  `entity.*` (each `on_created`/`_updated`/`_deleted`),
  `websocket.on_open`/`on_message`/`on_close`. Decide hooks:
  `intercept.on_request_pending`, `intercept.on_response_pending`, and
  `websocket.on_message_pending` (which needs `hold`).
- **Actions** (`actions` in plugin.json): run by the user from the traffic
  list's context menu on one request, never by core. The function gets
  `{ action, flow }` (`ActionHandler`), may answer a message for the status
  line, and may run up to five minutes; what it sends goes through
  `http.send`, so through the upstream chain. Test with `mock.action`.
- **Commands** (`commands` in plugin.json): what the plugin adds to
  reProxy's command line, under the plugin's own name — `reproxy
  <plugin> <action> --flags` — so you declare actions, not namespaces.
  Core parses the flags the command declared and writes its help, so the
  function gets `{ namespace, action, flags, args, json }`
  (`CommandHandler`) and answers with text, or `{ output, json, code }`.
  A plugin named for a core namespace (`findings`, `targets`, `flows` …)
  may not declare commands at all.
- **Decisions** (decide hooks): `decision.pass()` (or return nothing),
  `decision.edit(text)`, `decision.forward(text?)`, `decision.drop()`.
  Change messages with `edit.setHeader`, `edit.removeHeader` and
  `edit.setBody` on `message.editable()`; Content-Length is fixed up for
  you.
- **SDK modules**: `plugin`, `log`, `settings`, `storage`, `flows`,
  `findings`, `targets`, `entities`, `http`, `intercept`, `text`,
  `decision`, `edit`.
- **Messages** are decoded lazily: `head()`, `headers()`, `header(name)`,
  `contentType()`, `text()` (dechunked and decompressed), `json()`,
  `isBinary()`, `raw()`, `body()`, `editable()`.
- **Outbound requests** (`http.send`) always go through the user's upstream
  proxy chain. They're unrecorded unless `{ record: true }`, and go through
  reProxy's own proxy (recorded and interceptable) with
  `{ throughProxy: true }`. Limits: 16 in flight, 16 MiB per response,
  30 s default timeout.
- **DNS lookups** show in reProxy's traffic list as flows of their own, but
  plugins never see them: no hook fires for a lookup.

## Repository conventions

- Write in plain, direct English, in comments, notes, descriptions and
  docs alike. Comments say *why*, in full sentences; match the density of
  the existing plugins.
- TypeScript: `import { … , type X } from "reproxy"`, named exports, no
  default exports, two-space indent, double quotes, semicolons.
- Keep each plugin self-contained. Plugins don't import from each other.
  If two need the same helper (a JWT decoder, say), each keeps its own copy
  under `src/`.
- No test fixtures from real engagements: no real hosts, credentials or
  personal data. Use `*.test` hosts and obviously fake values.
- Commit only when asked. Commit messages say what changed and why.
- Keep AI out of the history. A commit message, a pull request or a code
  comment describes the change, never the tools that wrote it: no
  `Co-Authored-By` trailer for an assistant, no "generated with" line, no
  mention of a model or an agent anywhere in the repository.
