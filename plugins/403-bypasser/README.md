# 403-bypasser

Tries the well-known tricks for reaching a **401/403-protected endpoint** on
one request you pick, and records each one that works as a finding you can
report and fix. It is a right-click action — select a blocked request in the
traffic list, choose **403 Bypasser** — and nothing else: it has no traffic
or entity hooks, so it never runs on its own. This is a port of PortSwigger's
[403-bypasser](https://github.com/PortSwigger/403-bypasser), extended for
reProxy's plugin model.

## What it tries

Each probe is the request you chose with one change, and it keeps your own
Cookie and Authorization — the question is whether the *same* blocked user
can reach the resource by a trick, not whether an anonymous one can.

- **Path mutations** — the original's payloads
  (`%2e`, `%2f`, `..;`, `;%2f..`, `*`, …) inserted around the path, plus the
  usual structural tricks: a trailing slash, doubled slashes, `/.`, `/./`,
  `/..;/`, upper/lower case, a swapped-case last segment, and `.json` /
  `.html` / `;.css` suffixes.
- **Header injection** — the IP/forwarding headers (`X-Forwarded-For`,
  `X-Real-IP`, `X-Custom-IP-Authorization`, `X-Forwarded-Host`, …) set to
  `127.0.0.1`, added to the request.
- **URL-override headers** — the blocked path carried in `X-Original-URL` /
  `X-Rewrite-URL` (and variants) against a permitted base path.
- **Method swaps** — `POST`, `HEAD`, `OPTIONS` in place of the request's own
  method, for an ACL that only guards one verb.
- **HTTP/1.0 downgrade** — the same request sent on the wire as HTTP/1.0.

### A note on the HTTP/1.0 downgrade

reProxy sends a plugin's requests as raw bytes on the connection, so the
downgrade is real: the request line goes out as `HTTP/1.0`. It downgrades the
hop from reProxy to the target (or to your upstream proxy), not every hop end
to end, so read a hit as "an HTTP/1.0 path to this resource skips the check",
and confirm where that check lives.

## How a bypass is judged

The original reports anything that returns `200`. That is noisy, so this port
is stricter:

1. **Baseline.** The unchanged request is sent a few times. It must come back
   **blocked** (401/403 by default); if it doesn't, there is nothing to
   bypass and the run stops with a message. (Turn off *Require a blocked
   baseline* to test regardless.)
2. **Candidate.** A variant counts only if it **leaves** the blocked status,
   reaches a **content-serving** status (2xx; 3xx only if you allow it), and
   its body **differs** from the block page by more than the baseline's own
   noise — so an app that answers "access denied" with a `200` isn't a false
   hit. An override must also differ from the permitted base path, or it is
   just that page coming back.
3. **Confirmation.** Every candidate is re-sent on its own and recorded
   **only if it reproduces**. A one-off fluke is never reported.

3xx redirects are **off** by default: adding or removing a trailing slash, and
redirects to a login page, are common false positives. Turn them on when a
redirect to the resource itself is what you expect.

## What it records

One finding per confirmed bypass (type **403 Bypass**), naming the technique,
the exact mutation, the blocked baseline versus the status it reached, and the
remediation — normalise and decode the path before the ACL; don't trust
client IP / forwarding / URL-override headers at the app tier; apply the check
to every method and HTTP version. The finding links the recorded probe that
got through.

## It is active, so it is bounded

A run sends many requests to the host of the request you chose. All of it is
user-triggered, paced, and capped, and every probe carries a **cache-buster**
(a unique query parameter) so an odd request never shares a cache key with a
real user and the answer comes from the origin.

| Setting | Default | |
|---|---|---|
| Techniques to try | path, header, override, method, downgrade | |
| Extra path payloads | — | Added to the bundled list for the path technique. |
| Extra headers to inject | — | `Name: Value` lines; a bare name defaults to `127.0.0.1`. |
| URL-override headers | X-Original-URL, X-Rewrite-URL, … | Tried with the blocked path as their value. |
| Override base path | `/` | The permitted path the override technique requests. |
| Methods to try | POST, HEAD, OPTIONS | The request's own method is skipped. |
| Strip headers on HTTP/1.0 downgrade | off | On matches the original (request line + Host only). |
| Blocked statuses | 401, 403 | What counts as blocked, and what a bypass must leave. |
| Count 3xx redirects as a bypass | off | See above. |
| Require a blocked baseline | on | |
| Add a cache-buster to every probe | on | |
| Most requests to send | 400 | A hard cap across the baseline, every technique and confirmations. |
| Pause between requests | 120 ms | So a run doesn't burst at the target or its CDN. |
| Most bypasses to report | 50 | |
| Baseline samples | 3 | |
| Largest response body compared | 512 KiB | The length, used to spot a changed response, is measured in full. |

Every probe is sent recorded, so the whole run is visible in the Traffic list
and auditable.
