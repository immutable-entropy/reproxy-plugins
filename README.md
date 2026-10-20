# Writing reProxy plugins

A plugin is TypeScript that runs inside reProxy when something happens: a
request passes through the proxy, interception holds a message, a finding is
recorded. It can read the traffic and act on it: record findings, put URLs
in the Entity Explorer, send requests, and edit, forward or drop held messages.

No plugins are built into reProxy: every plugin is installed from a
repository, and this one is the default. Open the **Plugins** window (the
puzzle piece above the cog in the navigation bar), and add plugins from the
**Repositories** section. A plugin is installed disabled, into the data
directory's `plugins/` folder (`~/.reproxy/plugins` on macOS, Linux and BSD;
`%APPDATA%\reproxy\plugins` on Windows), and runs once you enable it. Your
own plugins can go straight into that folder; the Plugins window has a
button that opens it. The plugins here:

| Plugin | What it does |
|---|---|
| [`wordpress`](plugins/wordpress) | Recognises WordPress sites from the Entity Explorer and records the core version, plugins, themes, REST namespaces and exposed accounts as findings. Passive by default; an opt-in active scan requests a part's readme.txt/style.css to pin a version the traffic didn't state, once per part per engagement |
| [`sensitive-info`](plugins/sensitive-info) | Flags credentials, keys, tokens, password hashes and highly sensitive personal data (payment cards, bank and government identifiers, dates of birth) in requests, responses, WebSocket messages and the files the work recovered — headers, query strings, bodies and recovered source — as findings, recording the ones that are secrets in themselves hidden. A token or session identifier in a header is the tester's own session, so it is not reported; a secret a format proves to be one is reported wherever it appears |
| [`footprint`](plugins/footprint) | Maps an organisation's external footprint from its responses: the contact details it publishes (emails, telephone numbers, postal addresses), the social-media accounts and source-code repositories it links to (judged by whether they sit in the header/footer or carry rel="me", so the org's own accounts are told from third parties' links in the page content), and the cloud buckets, package-registry entries, third-party services and API/documentation endpoints it exposes |
| [`stack-disclosure`](plugins/stack-disclosure) | Flags what a response's headers give away about the stack — the web server and its version, the language/framework/CMS, the deployed build, internal host names and private addresses, framework session cookies, and debugging aids left on — as findings, once per host, with the setting that turns each off |
| [`saml-inspector`](plugins/saml-inspector) | Decodes SAML exchanges (including DEFLATE redirect binding) and flags subjects, attributes and assertion weaknesses as findings |
| [`precon`](plugins/precon) | Pre-engagement reconnaissance from the command line. `reproxy precon dns <domain>` looks a domain up in DNS reconnaissance sources (DNSDumpster); `reproxy precon ssl <domain>` looks it up in the Certificate Transparency logs through both crt.sh and ctlogs.dev, merging the two answers certificate by certificate. What the lookups find — host names, addresses, certificate issuers and validity — goes in the Entity Explorer, with names outside the domain under Targets → Related. Driven by the user, not by traffic; each command sends the domain name to third-party services |
| [`js-libraries`](plugins/js-libraries) | Recognises the JavaScript libraries the targets serve (from a script's URL or its banner, including scripts a target's page loads from a public CDN) and records each version as a finding; looks each exact version up on osv.dev and raises every known vulnerability as a finding with its osv.dev link, severity and fixed release. Sends package names and versions to osv.dev |
| [`spa-recon`](plugins/spa-recon) | Recognises single-page apps — Vue/Nuxt, React/Next.js, Svelte/SvelteKit and Angular — and the bundler build behind them; on in-scope hosts it fetches exposed JavaScript source maps and the Vite build manifest to recover the app's source-file structure, its framework and build versions, and the URLs it references. When a map carries the source it un-webpacks it automatically (on by default): the application's source files are written to the engagement's recovered files, the exposed-map finding links to them, and each recovered file is mined for the URLs it calls. Records a finding per SPA, exposed source map, exposed build manifest, framework and bundled-dependency version, and fills the Entity Explorer from the hosts and URLs it finds. The right-click action "Recover source from map" does the same on demand. Sends requests to the target (active) to fetch .map and manifest.json files |
| [`param-miner`](plugins/param-miner) | Discovers hidden request parameters and unkeyed inputs on one request you right-click: common query/body/cookie names, and the proxy, routing and caching headers that matter behind a CDN or load balancer. Judges each guess by reflection or a change from a baseline, bisects a reacting batch to the name responsible, and confirms every candidate on its own before recording it. A user-initiated action only — never automatic; every probe carries a cache-buster so it never shares a cache key with a real user (active) |
| [`laravel`](plugins/laravel) | Finds the misconfigurations a Laravel application gives away in its own traffic: debug mode left on (Ignition's and Whoops' pages and the JSON exception reply, with the stack traces, application paths, framework and PHP versions, server environment and APP_KEY they print), development tooling left routed (Telescope, Horizon, Pulse, the Debugbar, Clockwork, Ignition's own routes, log viewers), the files a document root pointed at the project rather than public/ exposes (.env, composer.json, storage logs, vendor), and session cookies missing Secure, HttpOnly or SameSite. Each is a finding with the setting that fixes it. Passive by default; an opt-in check asks each in-scope Laravel host for a short list of paths once per engagement — what was checked is written into the engagement and noted on the origin in the Explorer, so a reload, a restart or a second visit sends nothing more |

## Layout

```
my-plugin/
  plugin.json      what the plugin is, and which functions run on which hooks
  main.ts          the entry point: every function plugin.json names is exported here
  src/             anything else, imported from main.ts
  test/*.test.ts   unit tests (reproxy plugins test)
```

The directory name must equal the plugin's `name`. `main.ts` can import:

- its own files, by relative path (`./src/x`);
- `.json` files;
- the SDK, `reproxy` (and `reproxy/testing` in tests).

Nothing else can be imported: no npm packages, no Node built-ins, nothing
outside the directory. Vendor what you need under `src/`, from a tagged
release at least 14 days old, unminified, with a header comment giving its
upstream URL, version, copy date and SHA-256 (see `CLAUDE.md`). Installing a plugin
downloads its `.ts`, `.js`, `.json`, `.md` and `.txt` files, but not its tests
(`*.test.ts`, or anything under `test/`).

## plugin.json

```json
{
  "name": "my-plugin",
  "version": "1.0-1",
  "description": "What it does, in a sentence or two.",
  "author": { "name": "Ann Example", "email": "ann@example.com" },
  "status": "disabled",
  "sdk": "1",
  "finding_types": [{ "id": "token", "name": "Token", "color": "#ef6c00" }],
  "targets": [
    {
      "hook": "traffic.on_response_received",
      "function": "scan",
      "match": { "scope": "in_scope", "status": ["2xx"], "content_types": ["application/json", "text/*"] }
    },
    { "hook": "plugin.on_load", "function": "init" }
  ],
  "settings": [
    { "key": "min_length", "type": "number", "label": "Shortest token", "default": 16 },
    { "key": "api_token", "type": "secret", "label": "Ticketing API token" }
  ]
}
```

| Field | |
|---|---|
| `name` | Required. 2–64 lower-case letters, digits and dashes, equal to the directory's name. |
| `version` | Required. `major.minor`, `major.minor-sub` (sub is a build counter: 1.0-2 is newer than 1.0-1, which is newer than 1.0), or semver `major.minor.patch[-pre]`. |
| `description` | Optional. Shown in the Plugins window. |
| `author` | `name` is required; `email` is optional. |
| `status` | `enabled` or `disabled`: the default for a plugin put in the plugins folder by hand. One installed from a repository always starts disabled. |
| `sdk` | The SDK major version the plugin was written for (`"1"`). A mismatch is refused rather than half-working. |
| `finding_types` | Optional. Types the plugin's findings use. They are added to the catalog while the plugin is enabled, and never saved to the user's settings. |
| `targets` | Maps hooks to exported functions (see below). Each `function` must be exported by `main.ts`; this is checked when the plugin is found, without running it. A plugin needs at least one target, action or command. |
| `actions` | Optional. What the plugin offers to run on a request the user right-clicks in the traffic list (see [Actions](#actions)). |
| `commands` | Optional. What the plugin adds to reProxy's command line, under the plugin's own name: `reproxy <plugin> <action> --flags` (see [Commands](#commands)). |
| `settings` | Optional. What the user can set in the Plugins window (see below). |

Unknown fields are refused, so a typo is reported instead of ignored. Every
problem with a manifest is listed in the Plugins window and by
`reproxy plugins validate`.

### Targets

| Field | |
|---|---|
| `hook` | One of the hooks below. |
| `function` | An exported function of `main.ts`. It gets one argument, the event, and may be `async`. |
| `match` | Optional filter. Events it turns away never reach your code (see below). |
| `self` | Traffic hooks only. Lets the function see traffic this plugin sent itself (off by default). |
| `hold` | Intercept hooks only. Has the proxy hold what `match` accepts for this plugin even while interception is off (see below). |
| `priority` | Intercept hooks only. Lower runs first; ties go by plugin name. |
| `timeout_ms` | Intercept hooks only. How long reProxy waits for an answer (100–30000, default 2000). |

The same function can be on several hooks, and the same hook can map to
several functions.

### Hooks

**Lifecycle hooks.** These go ahead of the plugin's queue and run within 2 s.

| Hook | Event |
|---|---|
| `plugin.on_load` | `{ reason: "startup" \| "enable" \| "reload" \| "rescan", settings }` |
| `plugin.on_unload` | `{ reason: "disable" \| "reload" \| "rescan" \| "fault" \| "shutdown" }` |
| `plugin.on_status_change` | `{ from, to, reason: "user" \| "fault" }`. Called when the user enables or disables the plugin, or when it faults. |
| `plugin.on_settings_change` | `{ changed: { key: { old, new } }, settings }` |

**Observe hooks.** These report what has already happened. Calls are queued
and asynchronous, so they never slow the traffic down.

| Hook | When |
|---|---|
| `traffic.on_request_received` | A request was captured. |
| `traffic.on_request_forwarded` | A request went upstream, after any edit made while it was held. |
| `traffic.on_response_received` | A response arrived. |
| `traffic.on_response_forwarded` | A response went to the browser, after any edit. |
| `traffic.on_flow_complete` | An exchange finished: one call per completed request and response. |
| `traffic.on_flow_failed` | An exchange ended without a response. |
| `traffic.on_flow_dropped` | A held message was dropped. |
| `intercept.on_released` | A held message was forwarded or dropped: `{ flowId, direction }`. |
| `replay.on_sent` | A replay finished (the user's, an agent's or a plugin's recorded send). |
| `finding.on_finding_created` / `_updated` / `_removed` | `{ finding }` |
| `target.on_changed` | `{ targets }` |
| `engagement.on_opened` / `engagement.on_closed` | `{ name, path }` |
| `url.on_created` / `_updated` / `_deleted` | `{ entity }` (a `Url`): a URL was put in the Entity Explorer (requested, or discovered in a response), gained a request or a link, or had its key/value store edited; or was removed. |
| `host.on_created` / `_updated` / `_deleted` | `{ entity }` (a `Host`): the same for a host. It is updated when a request reaches one of its URLs. |
| `domain.on_created` / `_updated` / `_deleted` | `{ entity }` (a `Domain`): the same for a domain. It is updated when a request reaches one of its hosts. |
| `file.on_created` / `_updated` / `_deleted` | `{ file }` (a `RecoveredFile`): a file the work recovered was written under the engagement for the first time, recovered again with different bytes, or deleted. Recovering the same bytes again raises nothing, so a repeated recovery doesn't set your scanner off twice. |
| `file.on_batch_complete` | `{ batch }` (a `FileBatch`): a recovery of many files finished — a source map unpacked, say. Every file raised its own event too, but a recovery can be thousands of files and your queue holds 1024, so take the batch here and read it with `files.list({ batch: e.batch.id })` at your own pace. |
| `entity.on_created` / `_updated` / `_deleted` | `{ entity }`: any of the three. A URL put in the Explorer calls both `url.on_created` and `entity.on_created`. Narrow it with `types`. |
| `websocket.on_open` / `websocket.on_close` | `{ flow }`: a WebSocket connection's 101 completed, or it ended. |
| `websocket.on_message` | `{ flow, message }`: a WebSocket message was sent or received. |

**Entities.** The Entity Explorer (the "Explorer") is the engagement's map of
what the traffic touched. It holds three types of entity, each under the one
above it (`parent` is the parent's `key`):

| Type | `key` | Example |
|---|---|---|
| `domain` | the registrable domain | `example.com` |
| `host` | a name host: a DNS name or IP address on its own (no scheme), which DNS facts such as `addresses` belong to; a root for an IP or single-label name | `//api.example.com`, `//10.0.0.5` |
| `host` | an origin, under its name host | `https://api.example.com:8443` |
| `url` | the templated URL (`/users/12` → `/users/{id}`) | `https://api.example.com:8443/users/{id}` |

Every entity has `type`, `key`, `parent`, `label`, `scheme`/`host`/`path`,
`targetId`, `origin` (what first put it there: `traffic`, `link`, `referer`,
`target` or `plugin:<name>`), `visited` (false for one only discovered in a
response, never requested), `hits`, `links` (what discovered it), and `kv`, a
string key/value store any plugin can write with `entities.set`. A `Url`
also has `url`, `operations`, `examples`, `kinds` and `flowIds`; a `Host` has
`port`, `ip` and `servers`; a `Domain` has `suffix` and `icann`. A plugin's
own `on_created` events are skipped, like its own traffic.

By default the `on_created` and `on_updated` hooks only run for entities that
belong to a target: a target covers the entity's host, or the entity is the
domain or address a target names. A related host's entities, and those from
traffic no target covers, are left out unless the user turns on Settings →
Targets → "Run entity hooks for every entity, not only those in a target".
`on_deleted` always runs, and while no target is set up every entity counts.

Traffic events are `{ hook, flow }`. Requests are streamed: a request is
already on its way upstream when it is recorded, so for traffic that isn't
held, *received* and *forwarded* happen at the same moment. Observe hooks
can't change traffic. To change traffic, use the intercept hooks.

**Intercept hooks.** reProxy waits for the answer.

| Hook | Event |
|---|---|
| `intercept.on_request_pending` | `{ flow, message }`: interception is holding a request. |
| `intercept.on_response_pending` | `{ flow, message }`: interception is holding a response. |
| `websocket.on_message_pending` | `{ flow, message }`: a WebSocket message is held for editing (needs `hold`; see WebSocket below). |

These see only what the user's interception holds (each target's Hold
requests / Hold responses, while interception is on). Plugins see the message before the
user does, one at a time in priority order. Each returns one of these:

- `decision.pass()`, or nothing: no opinion.
- `decision.edit(text)`: replace the message. The next plugin, and then the
  user, sees the edit, and the original is kept.
- `decision.forward(text?)`: send it on now.
- `decision.drop()`: drop it now.

After `forward` or `drop` the user never sees the message, unless "Let
plugins forward or drop held messages" is off in the Plugins window. In that
case they count as an edit and a pass. A timeout, an error or an answer that
isn't a decision counts as a pass.

#### Holding traffic for the plugin: `hold: true`

On its own, an intercept hook only sees what the user's interception holds.
With `"hold": true` the proxy also holds every message the target's `match`
accepts, whether or not interception is on, so a plugin can rewrite traffic
on the way through. This is how you write a header injector or a response
rewriter, for example.

- The user never sees a message held only for plugins. Once the plugins have
  answered it goes on: forwarded as edited, or dropped if a plugin said so.
  "Let plugins forward or drop held messages" doesn't apply to these.
- The user turns holding off with "Let plugins hold traffic for themselves"
  in the Plugins window.
- Only matching traffic waits, and a held message is buffered whole. Keep
  `match` tight, because everything it accepts costs a round trip into the
  plugin.
- A plugin never holds its own traffic.

```json
{ "hook": "intercept.on_request_pending", "function": "addAuth", "hold": true,
  "match": { "scope": "in_scope", "hosts": ["api.app.test"] } }
```

#### WebSocket

A WebSocket connection shows in the traffic as its upgrade flow (the 101), with
a **Messages** tab listing the messages exchanged. Plugins see those messages
through the websocket hooks:

- `websocket.on_open` / `websocket.on_close` — the connection's life.
- `websocket.on_message` — every message, both directions. Filter the
  direction in Go with `match.directions`.
- `websocket.on_message_pending` — edit or drop a message before it is
  forwarded. It needs `hold: true`, and reProxy strips the connection's
  permessage-deflate compression at the handshake so messages can be rewritten
  (editing a shared-context compressed stream in place isn't reliable). The
  answer is a `decision`: `edit(text)` (or `edit(bytes)` for a binary
  message), `forward`, `drop`, or `pass`.

```ts
import { decision, type Hooks, type WebSocketPendingEvent } from "reproxy";

export function watch(e: Hooks["websocket.on_message"]) {
  if (e.message.text().includes("admin")) log.warn("saw admin on the socket");
}
export function tamper(e: WebSocketPendingEvent) {
  return decision.edit(e.message.text().replace(/"role":"user"/, '"role":"admin"'));
}
```

`message.text()`, `message.data()`, `message.direction` and `message.type`
read a WebSocket message. Only the messages of a targeted connection reach the
runtime; HTTP/2 and raw upgraded protocols other than WebSocket are relayed
but not framed.

Edits work on `message.editable()`, the text a held message is edited as. The
SDK's `edit.setHeader`, `edit.removeHeader` and `edit.setBody` change it, and
Content-Length is corrected when the edit is applied.

```ts
import { decision, edit, type PendingEvent } from "reproxy";

export function tag(e: PendingEvent) {
  return decision.edit(edit.setHeader(e.message.editable(), "X-Test-Run", "42"));
}
```

### Actions

An action is something the user runs by hand: they right-click a request in
the traffic list, and the menu lists the actions the running plugins offer
for it, under each plugin's name. Nothing else calls an action's function,
so an action costs nothing until it is picked.

```json
"actions": [
  {
    "id": "retry-as-guest",
    "label": "Retry without cookies",
    "description": "Sends the request again with its Cookie and Authorization headers removed.",
    "function": "retryAsGuest",
    "match": { "scope": "in_scope", "methods": ["GET"] }
  }
]
```

| Field | |
|---|---|
| `id` | Required. 1–64 lower-case letters, digits and dashes, unique in the plugin. |
| `label` | Required. The menu item: one line, at most 80 characters. |
| `description` | Optional. The menu item's tooltip. |
| `function` | Required. An exported function of `main.ts`. |
| `match` | Optional. The requests the action is offered for, written like a traffic hook's filter (`content_types` tests the response). Unlike a traffic hook's, with no `sources` it accepts requests from every source, plugins' included: the user chose the request. |

The function is called with `{ hook: "action", action, flow }`: the action's
`id` (so one function can serve several actions) and the request, as a
`Flow` like the traffic hooks get, read fresh when the action runs. It may
be `async`, and may answer with a short message for the user, either a
string or `{ message }`, which reProxy shows in the status line and writes
to the plugin's log. If it throws, the user sees the error. Type it with
`ActionHandler`:

```ts
import { http, type ActionHandler } from "reproxy";

export const retryAsGuest: ActionHandler = async ({ flow }) => {
  const headers = flow.request.headers().filter((h) => !/^(cookie|authorization)$/i.test(h.name));
  const r = await http.send(
    { url: flow.url, method: flow.method, headers: headers.map((h) => [h.name, h.value]) },
    { throughProxy: true },
  );
  return `answered ${r.status} without credentials (was ${flow.status})`;
};
```

Each turn of an action has the usual time budget, and the action as a whole
may run for up to five minutes, because it is expected to send requests and
wait for them. Everything it sends goes through `http.send`, so **through
the upstream proxy chain** like any plugin's traffic (reProxy refuses to
send a plugin's request any other way). Send with `{ throughProxy: true }`
so the requests show in the traffic list beside the one the user picked.

An action is active testing the user asked for, on a request they chose;
keep to what its label says, and to the hosts the targets cover
(`targets.match(url)`) unless the label says otherwise.


### Commands

A command is something the user types. reProxy's command line is

```
reproxy <namespace> <action> [--flags] [arguments]
```

and **a plugin's namespace is its own name**. Everything the `param-fuzzer`
plugin adds is `reproxy param-fuzzer <action>`, so plugin.json declares
actions, not namespaces, and no two plugins can collide: they can no more
share a namespace than a directory.

Core's namespaces (`findings`, `targets`, `plugins`, `flows`, and the rest
of the list in reproxy's `internal/cli/namespaces.go`) are reserved, so a
plugin *named* for one may not declare commands. It doesn't run at all, and
says why in `reproxy plugins validate` and in the Plugins window — rename
it, or drop its commands.

```json
"commands": [
  {
    "action": "run",
    "summary": "Fuzz one parameter of a captured request",
    "description": "Sends the request once per word, and records a finding for each answer that differs.",
    "args": "<parameter>",
    "function": "fuzzRun",
    "flags": [
      { "name": "flow", "type": "number", "required": true, "description": "the flow id to fuzz" },
      { "name": "wordlist", "default": "common", "description": "which list to send" },
      { "name": "quiet", "type": "boolean", "description": "only report what differed" }
    ]
  }
]
```

In a plugin called `param-fuzzer`, that is `reproxy param-fuzzer run
--flow 42 id`.

| Field | |
|---|---|
| `action` | Required. 1–32 lower-case letters, digits and dashes, unique in the plugin. |
| `summary` | Required. The line help lists the command with: one line, at most 80 characters. |
| `description` | Optional. The paragraph `--help` adds under the usage line. |
| `args` | Optional. The positional arguments, for the usage line (`"<file>..."`). They reach the function as typed. |
| `flags` | Optional. The flags the command takes: `name` (lower-case, dashes allowed), `type` (`string`, `number`, `boolean` or `list`; inferred from `default`, else `string`), `description`, `required`, `default`, `placeholder`. `--instance`, `--json` and `--help` belong to reProxy and can't be declared. |
| `function` | Required. An exported function of `main.ts`. |

Core does the parsing. It reads the flags against what was declared, fills
in the defaults, refuses a flag the command doesn't take, and writes the
help — so the function is only called with an invocation it can answer, and
a command nobody typed never enters the runtime. The function is called with
`{ hook: "command", namespace, action, flags, args, json }`: `namespace` is
the plugin's own name as the user typed it, `flags` holds
every declared flag by name, with the type it was declared as (`list` is a
`string[]`), and `json` says the user asked for machine-readable output. It
may be `async` and may run up to five minutes, like an action.

It may answer with a string to print, or with `{ output, json, code }`:
`output` is the text, `json` is what `--json` prints instead, and `code` is
the exit status (0 unless it says otherwise). Throwing prints the error and
exits non-zero. Type it with `CommandHandler`:

```ts
import { flows, type CommandHandler } from "reproxy";

export const fuzzRun: CommandHandler = async ({ flags, args, json }) => {
  const flow = flows.get(flags.flow as number);
  if (!flow) return { output: `no flow ${flags.flow}`, code: 1 };
  const results = await fuzz(flow, args[0], flags.wordlist as string);
  if (json) return { output: summarize(results), json: results };
  return summarize(results);
};
```

Commands run in whichever reProxy process the user's command line is
talking to, so they see that process's traffic, engagement and settings —
the same objects the plugin's hooks see.

### Match filters

`match` is evaluated in Go, before anything reaches the plugin. Every field
you set must match. Within a field, any entry may match.

| Field | Matches | Hooks |
|---|---|---|
| `scope` | `any` (default), `in_scope` (a flow a target covers, or every flow while no targets are configured), `out_of_scope` | traffic, intercept, entity |
| `targets` | target IDs | traffic, intercept, entity |
| `hosts` | `app.test`, `*.app.test` (subdomains), or any glob; ports are ignored. A file hook tests the host the file was recovered from | traffic, intercept, entity, file |
| `paths` | globs over the path without its query: `/api/*`. On a file hook, globs over the recovered file's path, which is relative to the engagement's recovered files and has no leading slash: `app.test/*`, `*.ts` | traffic, intercept, entity, file |
| `path_regex` | an RE2 regular expression over the path and query | traffic, intercept, entity |
| `methods` | `GET`, `POST`, … | traffic, intercept |
| `status` | `404`, `2xx`, `500-599` | traffic, intercept |
| `content_types` | media type globs: `application/json`, `text/*`, `application/*+json`. Request hooks test the request's Content-Type, all others the response's; a file hook tests the recovered file's media type, so `text/*` never hands you a font. | traffic, intercept, file |
| `sources` | traffic: `proxy`, `replay`, `agent`, `plugin` (default: all but `plugin`); findings and recovered files: `user`, `agent`, `plugin` | traffic, finding, file |
| `types` | finding type IDs; for entity hooks, entity types: `domain`, `host`, `url`; for file hooks, a recovered file's `kind` (`source-map`, `source-map-dependency`, or whatever the plugin that recovered it used) | finding, entity, file |
| `directions` | WebSocket message direction: `sent` (browser→server), `received` | websocket |

Filter as tightly as you can. Traffic your filter turns away costs nothing.
Traffic it accepts is copied onto your plugin's queue (up to 1024 events). If
the plugin falls behind, events are dropped and counted, and the proxy never
waits for it.

### Settings

| Field | |
|---|---|
| `key` | Lower-case letters, digits and `_`. |
| `type` | `string`, `number`, `boolean`, `enum` (needs `options`), `list` (of strings), or `secret`. If left out, it is inferred from `default`. |
| `label`, `description` | What the Plugins window shows. |
| `default` | The value until the user changes it. A secret has no default. |

The user's changes are saved in reProxy's settings file, never in your
`plugin.json`. Secrets go to `secrets.json`, which is readable only by the
user. Read values with `settings.get("key")`. When the user changes them, the
plugin's `plugin.on_settings_change` is called.

## The SDK

```ts
import { plugin, log, settings, storage, flows, findings, files, targets, entities, http, intercept, text, decision, edit } from "reproxy";
```

| | |
|---|---|
| `log.debug/info/warn/error` | The plugin's log, shown in the Plugins window. `console.*` goes there too. |
| `settings.get(key)`, `settings.all()` | Current setting values, secrets included. |
| `storage.get/set/delete/keys` | Persistent JSON storage for the plugin (1 MiB). `storage.engagement.*` is kept in the open engagement's database and travels with it. |
| `flows.get(id)`, `flows.list(q)`, `flows.search(text, { regex })` | The traffic list. |
| `findings.record(draft)`, `findings.list(q)`, `findings.types()` | Record a finding. `notes` is required, and saying why the plugin raised it is the point. A finding with the same value merges in as another sighting. Set `hidden: true` when the value is a secret in itself — a password, a key, a session token, a card number, a national identifier — and reProxy keeps it masked on screen until the user clicks the eye beside it; leave it off for data that is sensitive but not secret, such as an email address. It changes the display only: the value is still stored, searched and handed to agents and plugins. Pass `files: [id, …]` (ids from `files.addAll`) to link the finding to recovered files, so it leads straight to the source reconstructed from it — the UI opens each, and `get_file` reads it (see `spa-recon`). |
| `files.add(draft)`, `files.addAll(drafts)`, `files.list(q)`, `files.batches()`, `files.read(idOrPathOrFile, maxBytes?)` | The files the work recovered (see below). |
| `targets.list()`, `targets.match(url)` | The targets in scope. |
| `entities.addHost({ host, addresses, from, detail })` | Puts a host in the Explorer without a URL: a DNS name or IP address (no scheme, port or path), with its domain. `addresses` are the IP addresses the name resolves to; each goes in as a host of its own, and the name lists them in `addresses`. Resolves `{ entity, created }` for the name. Use it for what you learn about hosts rather than URLs (DNS records, certificate names); `from` makes one no target covers Related, as for `addUrl`. |
| `entities.addUrl({ url, flowId, from, detail })`, `entities.get(keyOrUrl)`, `entities.list({ type, targetId, host, parent })`, `entities.children(key)` | The Entity Explorer. `addUrl` resolves `{ entity, created }`; it puts the URL in as discovered, with its host and domain, and a URL already there just gains the link. `get` takes an entity's key, a bare host name or address (its name host, `//name`), or a concrete URL (`https://app.test/users/12`) and returns the URL it falls under. An added URL is templated like visited ones (`/users/12` → `/users/{id}`, and `{orderId}` placeholders too), so it merges with what the traffic put there. Core already reads every response for the URLs it refers to (HTML, CSS, scripts, JSON, robots.txt, sitemaps, OpenAPI, and headers such as Location and Content-Security-Policy), so add what only your plugin can find. A URL on a host no target covers is kept but listed under Targets → Related rather than drawn, until the user promotes the host. That takes something on a target leading to it: the flow (`flowId`) the URL was found in, or, when no flow was involved, `from`, an absolute URL on a host a target covers (`https://example.com/` for a lookup made for that target; see `precon`). |
| `entities.set(key, name, value)`, `entities.unset(key, name)` | Write an entity's `kv` store. They resolve with the entity, and call its `on_updated` hooks; setting the value a key already has changes nothing and calls no hook. |
| `http.send(request, options)` | Outbound HTTP (see below). |
| `intercept.held()`, `intercept.forward(id, text?)`, `intercept.drop(id)` | Messages held for the user. |
| `text.scan(input, patterns)`, `text.urls(input, base)` | Regular expressions and URL extraction, run in Go. |

A `Flow` carries its `request` and `response` as `Message`s. Nothing is
decoded until you ask: `head()`, `headers()`, `header(name)`,
`contentType()`, `text()` (dechunked and decompressed), `json()`, `raw()`,
`body()`.

### Recovered files

A **recovered file** is something your plugin pulled out of the traffic and
asked reProxy to keep: the original source a JavaScript source map carries, a
bundle taken apart, an asset worth a closer look. You decide what is worth
recovering and produce the bytes; core writes the file under the engagement
(`<engagement>/recovered/…`), records where it came from, and calls the file
hooks — which is the point of handing it over rather than keeping the text in
a variable. A plugin that scans text for secrets hooks `file.on_created` and
reads recovered client source with the code it already has for response
bodies, so recovering a build makes every scanner in the user's set work on it.

```ts
import { files, log } from "reproxy";

// Recovering: one recovery, one batch.
const res = await files.addAll(
  sources.map((s) => ({
    path: `${host}/${bundle}/${s.path}`,   // relative; core cleans it
    content: s.text,
    kind: s.app ? "source-map" : "source-map-dependency",
    flowId: flow.id,                        // where it came from
    batchLabel: mapUrl,
  })),
);
log.info(`recovered ${res.files} files (${res.unchanged} already there)`);

// Scanning what someone else recovered.
export async function scan(e: Hooks["file.on_created"]) {
  const { text } = await files.read(e.file);
  for (const m of textScan(text)) await findings.record({ /* … */ });
}
```

- **Paths are relative and untrusted.** Give the tree you want
  (`app.test/main/src/api.ts`); core cleans every segment (a scheme, `..`, a
  drive letter, an illegal character) and never writes outside the
  engagement's recovered files. A path with nothing safe left is refused.
- **Recovering the same path with the same bytes changes nothing** and raises
  no event, so a recovery can be run twice without setting every scanner off
  again. Different bytes replace the file and raise `file.on_updated`.
- **Use `addAll` for a recovery**, not `add` in a loop: its files share one
  batch, it writes under one lock, it enforces the recovery limits (20,000
  files, 512 MiB) as a whole, and it is what ends with
  `file.on_batch_complete`. `add` is for a single file.
- **You are not called for what you recovered yourself** unless the target
  sets `self`, exactly as with your own traffic.
- **The bytes stay on disk.** A `RecoveredFile` is the record — `path`,
  `size`, `mediaType`, `text` (whether it can be read as text), `kind`,
  `author`, `batch`, `flowId`, `url`, `host`, `entity`, `sha256`. Read the
  content with `files.read`, which resolves `{ file, text, truncated }` and
  returns at most 8 MiB.
- There is no filesystem in the runtime, and this is not one: a recovered
  file belongs to the engagement, travels with it, and is listed in reProxy's
  Files section, in `reproxy files ls` and to the user's AI agents. Use
  `storage` for a plugin's own state.

### Outbound requests

```ts
const r = await http.send({ url: "https://api.app.test/v1/me", headers: { Authorization: "Bearer x" } });
if (r.ok) log.info(r.json());
```

- Requests always go out through the upstream proxy chain configured in
  Settings → Outbound Traffic.
- By default they don't go through reProxy's own proxy, so they aren't
  recorded. Pass `{ record: true }` to list one in the traffic anyway.
- Pass `{ throughProxy: true }` to send through reProxy's proxy, so the
  exchange is recorded, interceptable and visible to other plugins like the
  browser's traffic. The flow's source is `plugin` and its origin is your
  plugin's name.
- Your own hooks skip your own traffic unless a target sets `self`. Your
  intercept hooks always skip it.
- A send made from a hook that is handling your own traffic counts one level
  deeper. Sends past depth 3 are refused with `E_RECURSION`, so plugins can't
  feed each other forever.
- Plugins can reach any host. The same-domain rule that binds AI agents
  doesn't apply to code you installed.
- Send the same request once. Keep what you have already asked for in
  `storage.engagement` — not only in a variable, which lasts until the next
  reload — and look there before sending, so a restart or a second visit to
  the site doesn't repeat the work against somebody's server. Write it down
  before the request goes out, remember the answers that found nothing as
  well, and reset your in-memory copy on `plugin.on_load` and
  `engagement.on_opened`.
- Responses over 16 MiB are refused. A plugin can have at most 16 requests in
  flight.

## The runtime, and what to expect from it

- The runtime is [goja](https://github.com/dop251/goja), a JavaScript engine
  written in Go, with one runtime per plugin. TypeScript is bundled by
  esbuild's Go API when the plugin loads. There's no Node, so `fetch`,
  `require`, `process`, the filesystem and the DOM aren't available.
- Globals provided: `console`, `setTimeout`/`setInterval`, `queueMicrotask`,
  `structuredClone`, `TextEncoder`/`TextDecoder`, `atob`/`btoa`.
- Code is lowered to ES2017 (async functions run natively). Modern syntax is
  fine. Regular expressions with Unicode property escapes (`\p{L}`) aren't
  supported in JavaScript; use `text.scan` instead.
- goja is far slower than V8, so do heavy matching with `text.scan`. Its
  patterns are Go's RE2: no backreferences or lookaround, and repeat counts
  up to 1000. In exchange, matching takes linear time.
- `text.scan` is fast, but not free, and a pattern's shape decides how fast.
  Each pattern it is given is a pass of its own, so compose alternatives into
  one pattern rather than passing twenty. Go's regexp jumps ahead with a
  plain text search only when a pattern begins with one literal string: a
  large alternation has none, and submatches cost more again. Measured on a
  512 KiB body, `(?i)"?(name|...60 more...)"?\s*[:=]\s*"(.{1,256})"` takes
  over half a second — more than two turns' budget — while `AKIA[0-9A-Z]{16}`
  takes under a millisecond. If your pattern has no leading literal, gate it
  in JavaScript first: `body.toLowerCase().indexOf("password")` and its like
  cost about 7 ms for fifty needles over that same body, and you can then run
  the expensive pattern on slices around what they found.
  `sensitive-info/src/detectors.ts` does exactly this, and
  `plugins/sensitive-info/test/cost.test.ts` is how to keep it honest.
- Each turn of plugin code (a hook call, a timer, the code after an `await`)
  has 250 ms to run before it is interrupted. Waiting on the network doesn't
  count.
- A plugin that fails 5 times within a minute is stopped for the session
  ("faulted"). Fix it and press Reload in the Plugins window.
- TypeScript types are stripped, not checked. Run `reproxy plugins types <dir>`
  to write the SDK and a `tsconfig.json` beside your plugin, so your editor
  checks it.
- Plugins are trusted code: they see your traffic and can send it anywhere.
  Install only plugins you have read.

## Testing

```
reproxy plugins validate <dir>   check plugin.json and the exported functions
reproxy plugins test <dir>       run test/*.test.ts (and any other *.test.ts)
reproxy plugins test -v -run JWT <dir>
```

Tests run in the same runtime plugins run in, against a throwaway engagement
with real stores. Findings really merge and URLs really template, so a
test checks what the plugin would do in the app. Outbound requests aren't
sent: `mock.respond` sets what comes back. Everything is reset before each
test.

```ts
import { describe, it, expect, mock } from "reproxy/testing";
import { looksLikeToken } from "../src/tokens";

describe("tokens", () => {
  it("knows one", () => expect(looksLikeToken("tok_8f2kq9d1")).toBe(true));

  it("records what a response leaks", async () => {
    const flow = mock.flow({
      url: "https://app.test/api",
      responseHeaders: { "Content-Type": "application/json" },
      responseBody: `{"t": "tok_8f2kq9d1"}`,
    });
    // Runs your targets for the hook as core would, match filters included.
    expect(await mock.dispatch("traffic.on_response_received", flow)).toBe(1);
    expect(mock.findings()[0].value).toBe("tok_8f2kq9d1");
  });
});
```

| `reproxy/testing` | |
|---|---|
| `describe`, `it`/`test`, `beforeEach`, `afterEach` | Grouping and setup. Async tests are awaited, and each has 5 s. |
| `expect(x)` | `toBe`, `toEqual`, `toBeTruthy`, `toBeFalsy`, `toBeUndefined`, `toBeDefined`, `toBeNull`, `toBeGreaterThan`, `toBeLessThan`, `toContain`, `toMatch`, `toHaveLength`, `toThrow`, plus `.not`, `.resolves` and `.rejects`. |
| `mock.flow(fixture)` | Puts a flow in the store: `url`, `method`, `requestHeaders`, `requestBody`, `status`, `responseHeaders`, `responseBody`, `source`, `targetId`, `origin`, and `wsMessages` (`{ direction, type, text }[]`) for a WebSocket connection's messages. |
| `mock.dispatch(hook, subject)` | Calls your targets for the hook whose filters accept the subject (a flow, a fixture, or an entity), and resolves with how many ran, once they have settled. An entity hook given a flow puts it in the Explorer first and dispatches the entity of the hook's type it reached: the URL for `url.*` and `entity.*`, the host for `host.*`, the domain for `domain.*`. A WebSocket message hook is dispatched once per message the flow carries, so one call drives the whole conversation; `websocket.on_open` and `on_close` are dispatched for the connection. |
| `mock.entity(flowOrFixture, type)` | Puts a flow in the Explorer as core's indexer does (its URL, host and domain, and the URLs its response links to), and returns the URL it reached, or with `"host"`/`"domain"` its host or domain. |
| `mock.action(id, flowOrFixture)` | Runs one of your actions on a flow, as the context menu would. Resolves with `{ ran, message }`: `ran` is false (and nothing is called) when the action's `match` turns the flow away, which is how to test that the menu wouldn't offer it; `message` is what the action answered. Rejects with what the action threw. |
| `mock.findings()`, `mock.entities()` | What was recorded. |
| `mock.target(kind, value)`, `mock.related()` | Add a target as the user would (`"domain"`, `"wildcard"`, `"regex"`, `"ip"`, `"cidr"`), and list the hosts under Targets → Related. Adding a target calls no hook: pass `targets.list()` to your `target.on_changed` function yourself. |
| `mock.respond(urlPattern, { status, headers, body })`, `mock.sent()` | Script outbound responses, and see what was sent. |
| `mock.settings({ key: value })` | Override settings for one test. |

Before committing, run every plugin's checks from this repo's root:

```
for d in plugins/*/; do reproxy plugins validate "$d" && reproxy plugins test "$d" || break; done
```

~~
