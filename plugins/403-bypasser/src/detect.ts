// Judging whether a variant got past the block.
//
// A variant is only interesting measured against what the picked request does
// on its own. So main first learns a baseline — the unchanged request, sent a
// few times, to a blocked status (401/403 by default) — and everything here
// compares a probe's response against it. Nothing sends anything; the
// orchestration in main.ts does, so this is all plain values.
//
// The rule: a variant counts as a bypass when it is no longer blocked, its
// status is one that serves content (2xx, or 3xx when the user allows it), and
// its body differs from the block page by more than the baseline's own noise.
// Requiring the body to differ keeps an app that answers "access denied" with
// a 200 from reading as a win. For the URL-override technique the response must
// also differ from the permitted base path, or it is just that base path's
// own content coming back.

/** What one response reduces to for comparison. */
export interface Signal {
  status: number;
  /** The decoded body length, the stable measure across compression. */
  length: number;
  /** A capped prefix of the body, to tell apart two responses of equal length. */
  body: string;
  /** Whether the response carried a readable body at all. */
  hasBody: boolean;
}

/** What the baseline samples established about the blocked response. */
export interface Baseline {
  /** The status the samples shared, or -1 when they disagreed. */
  status: number;
  minLength: number;
  maxLength: number;
  /** How far a length may stray from that range before it counts as changed. */
  pad: number;
  lengthStable: boolean;
  hasBody: boolean;
  /** A capped body prefix of a sample, for the content comparison. */
  body: string;
}

export type Why = "status" | "length" | "body" | "";

export function signalOf(status: number, length: number, body: string): Signal {
  return { status, length, body, hasBody: body.length > 0 };
}

/** isBlocked reports whether a status is one of the blocked ones. */
export function isBlocked(status: number, blocked: number[]): boolean {
  return blocked.indexOf(status) >= 0;
}

/** servesContent reports whether a status is one worth comparing: a 2xx, or
 *  a 3xx when redirects are allowed. */
export function servesContent(status: number, includeRedirects: boolean): boolean {
  if (status >= 200 && status < 300) return true;
  if (includeRedirects && (status === 301 || status === 302 || status === 303 || status === 307 || status === 308)) return true;
  return false;
}

/**
 * blockedBaselineOf reduces the baseline samples to what the comparisons
 * need. A status the samples disagree on becomes -1; a length that varied by
 * more than a small fraction is marked unstable so a dynamic block page
 * doesn't make every variant look like a hit.
 */
export function blockedBaselineOf(samples: Signal[]): Baseline {
  const statuses = samples.map((s) => s.status);
  const lengths = samples.map((s) => s.length);
  const status = statuses.every((s) => s === statuses[0]) ? statuses[0] : -1;
  const minLength = Math.min(...lengths);
  const maxLength = Math.max(...lengths);
  const spread = maxLength - minLength;
  const lengthStable = maxLength === 0 ? true : spread <= Math.ceil(maxLength * 0.05);
  const pad = spread + 24;
  const withBody = samples.find((s) => s.hasBody);
  return {
    status,
    minLength,
    maxLength,
    pad,
    lengthStable,
    hasBody: samples.some((s) => s.hasBody),
    body: withBody ? withBody.body : "",
  };
}

/** lengthChanged is true when a body length falls outside the baseline's
 *  range by more than its pad, and only when length was stable enough to judge. */
export function lengthChanged(bl: Baseline, s: Signal): boolean {
  if (!bl.lengthStable) return false;
  return s.length < bl.minLength - bl.pad || s.length > bl.maxLength + bl.pad;
}

/** differs says how a response differs from the block page, if it does: a
 *  response with no body is judged by its status alone (a HEAD, say). */
export function differs(bl: Baseline, s: Signal): Why {
  if (!s.hasBody) return "status";
  if (lengthChanged(bl, s)) return "length";
  if (bl.hasBody && s.body !== bl.body) return "body";
  return "";
}

/** Options for judging a variant. */
export interface Judge {
  blocked: number[];
  includeRedirects: boolean;
  /** The URL-override control (the permitted base path's response), when the
   *  variant is an override one; a hit must differ from this too. */
  control?: Signal;
}

/**
 * reacted returns why a variant counts as a bypass, or "" when it doesn't:
 * it must have left the blocked status, reached a content-serving status, and
 * differ from the block page — and, for an override, from the base path too.
 */
export function reacted(bl: Baseline, s: Signal, j: Judge): Why {
  if (isBlocked(s.status, j.blocked)) return "";
  if (!servesContent(s.status, j.includeRedirects)) return "";
  const why = differs(bl, s);
  if (!why) return "";
  if (j.control) {
    // An override that merely returns the permitted base path's own content
    // hasn't reached the protected resource.
    const c = j.control;
    const sameAsControl = s.length === c.length && s.body === c.body;
    if (sameAsControl) return "";
  }
  return why;
}
