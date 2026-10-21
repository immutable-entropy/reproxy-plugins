// The judgement param mining rests on: what a response "looks like", when
// two of them differ by more than the target's own noise, and which guessed
// names a response reveals. None of it sends anything — the orchestration
// in main.ts does — so all of it tests with plain values.
//
// A guess is only worth anything measured against what the same request
// does without it. So main first learns a baseline (the request with no
// guesses, sent a few times) and the target's jitter, and everything here
// compares a probe against that.

/** What one response reduces to for comparison. */
export interface Signal {
  /** The HTTP status. */
  status: number;
  /** The length of the response body as text (decoded), the stable measure
   *  across compression and chunking. */
  length: number;
}

/** What the baseline samples established about an unmodified response. */
export interface Baseline {
  /** The status every sample shared, or -1 when they disagreed (so status
   *  is too unstable to judge a guess by). */
  status: number;
  /** The range of body lengths the samples spanned. */
  minLength: number;
  maxLength: number;
  /** How far a length may stray from that range before it counts as a
   *  change: the samples' own spread, widened by what a control probe of
   *  junk names moved it (set by main). */
  pad: number;
  /** True while length is steady enough to judge a guess by. */
  lengthStable: boolean;
}

export function signalOf(status: number, length: number): Signal {
  return { status, length };
}

/** statusChanged is true when the baseline had a stable status and this
 *  probe's differs from it. */
export function statusChanged(base: Baseline, s: Signal): boolean {
  return base.status !== -1 && s.status !== base.status;
}

/** lengthChanged is true when the body length falls outside the baseline's
 *  range by more than its pad — and only when length was stable enough to
 *  mean anything. */
export function lengthChanged(base: Baseline, s: Signal): boolean {
  if (!base.lengthStable) return false;
  return s.length < base.minLength - base.pad || s.length > base.maxLength + base.pad;
}

/** howChanged says what, if anything, a probe moved relative to baseline. */
export function howChanged(base: Baseline, s: Signal): "status" | "length" | "" {
  if (statusChanged(base, s)) return "status";
  if (lengthChanged(base, s)) return "length";
  return "";
}

/**
 * baselineOf reduces the baseline samples to what the comparisons need. A
 * status the samples disagree on is dropped (-1); a length that varied by
 * more than a small fraction is marked unstable, so a dynamic page doesn't
 * make every guess look like a hit.
 */
export function baselineOf(samples: Signal[]): Baseline {
  const statuses = samples.map((s) => s.status);
  const lengths = samples.map((s) => s.length);
  const status = statuses.every((s) => s === statuses[0]) ? statuses[0] : -1;
  const minLength = Math.min(...lengths);
  const maxLength = Math.max(...lengths);
  const spread = maxLength - minLength;
  // A page that already varies by more than 5% of its size on its own is
  // too noisy to judge by length; lean on status and reflection instead.
  const lengthStable = maxLength === 0 ? true : spread <= Math.ceil(maxLength * 0.05);
  // The starting pad is the observed spread plus a small floor, so ordinary
  // jitter never reads as a change.
  const pad = spread + 24;
  return { status, minLength, maxLength, pad, lengthStable };
}

/** A guessed name, where it goes, and the unique value it was sent with. */
export interface Candidate {
  name: string;
  location: Location;
  value: string;
}

export type Location = "query" | "header" | "body" | "cookie";

/**
 * reflected returns the candidates whose unique value appears in the
 * response text — an exact match, because each name carried a value of its
 * own. The shared run prefix is searched once first, so a response that
 * reflects nothing costs a single indexOf however many names were in the
 * batch.
 */
export function reflected(text: string, prefix: string, candidates: Candidate[]): Candidate[] {
  if (!text || text.indexOf(prefix) < 0) return [];
  return candidates.filter((c) => text.indexOf(c.value) >= 0);
}

/** canaryValue builds a candidate's value: the run's random prefix, so it
 *  can't collide with page content, and an index that makes it unique. */
export function canaryValue(prefix: string, index: number): string {
  return prefix + index.toString(36);
}
