# param-miner

Discovers **hidden request parameters** and **unkeyed inputs** on one
request you pick. It is a right-click action — select a request in the
traffic list, choose **Param Miner** — and nothing else: it has no traffic
or entity hooks, so it never runs on its own. This is a port of the idea
behind PortSwigger's Param Miner, built for reProxy's plugin model.

It guesses names against the request you chose: common query, body and
cookie parameter names, and the proxy, routing and caching headers that
matter behind a CDN or a load balancer — the inputs that change a response
without being part of its cache key.

## Why it is careful behind a CDN

Every probe carries a **cache-buster**: a query parameter whose name is
unique to the run and whose value is unique to the request. Behind a shared
cache that keeps a probe from sharing a cache key with a real user, so a
guessed header can be tested for its effect on the response without that
response being stored and served to anyone else. It is also a correctness
measure: the answer comes from the origin, not from a cached copy that would
hide what the guess did.

The plugin **discovers** these inputs; it does not attempt cache poisoning.
A header that changes a cacheable response is reported as a lead, for you to
confirm by hand.

## How a guess is judged

1. **Baseline.** The request is sent a few times with no guesses, to learn
   its status, its body length, and how much both move on their own.
2. **Batches.** Names are sent in batches, each name carrying a value of its
   own.
3. **Two signals.** A name is a candidate when the response to its batch
   either **reflects** that name's value, or **differs** from the baseline
   by more than its noise (a changed status, or a length outside the
   baseline's range).
4. **Bisection.** A batch that reacts is halved and re-sent until the single
   name responsible is isolated.
5. **Confirmation.** Every candidate is re-sent on its own, and recorded
   **only if it reacts again**. A guessed name that doesn't confirm is never
   reported.

If the target answers differently to *any* unknown input at a location (a
control probe of junk names changes its status), behavioural detection is
switched off there and only reflected names are reported — with a note
saying so, rather than flooding you with every guess.

## What it records

One finding per confirmed parameter (type **Hidden Parameter**), with the
name, where it goes (query / header / body / cookie), and how it gave itself
away (reflected / status / length). A reflected value also carries a note to
check it for XSS and open redirects; a reacting header carries the unkeyed-
input / cache-poisoning note.

## It is active, so it is bounded

Mining sends many requests to the host of the request you chose. All of it
is user-triggered, paced, and capped:

| Setting | Default | |
|---|---|---|
| Where to mine | query, header | Add `body` (when the request has a form/JSON body) and `cookie` as needed. |
| Extra names to guess | — | Added to the bundled list. |
| Most requests to send | 300 | A hard cap across baseline, batches, bisection and confirmation. |
| Names per request | 24 | Larger is faster; smaller is gentler and cheaper to bisect. |
| Pause between requests | 120 ms | So a run doesn't burst at the target or its CDN. |
| Most parameters to report | 50 | |
| Baseline samples | 3 | |
| Largest response scanned for reflection | 1024 KiB | The length, used to spot a changed response, is measured in full. |

Every probe is sent recorded, so the whole run is visible in the Traffic
list and auditable.
