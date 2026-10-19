// Composing many patterns into one, and finding out afterwards which of
// them matched.
//
// text.scan runs each pattern it is given in a pass of its own, so looking
// for forty formats one pattern at a time would read the body forty times.
// RE2 matches an alternation in a single pass whatever its size, so every
// format of a kind is composed into one pattern — with no capturing groups
// at all, because asking Go's regexp for submatches costs more than the
// match itself — and the rule behind a hit is worked out by running the
// rules over the hit alone, which is a few hundred characters however big
// the body was.
//
// The patterns here are RE2 (Go's syntax, see the SDK's Pattern): no
// backreferences or lookaround, and counted repeats reach 1000.

import { text } from "reproxy";

export interface Branch {
  /** The rule this branch belongs to. */
  id: string;
  /** The RE2 source of the branch. */
  pattern: string;
}

/** A composed pattern, with the branches kept for identifying a hit. */
export interface Composed {
  name: string;
  source: string;
  branches: Branch[];
}

/** One hit: which branch it was, the text it matched, and that branch's
 *  own groups. */
export interface Found {
  id: string;
  match: string;
  groups: string[];
  index: number;
}

/** compose joins branches into one groupless alternation. An empty list
 *  composes to a pattern that is never run (see scan). */
export function compose(name: string, branches: Branch[]): Composed {
  return { name, source: branches.map((b) => `(?:${b.pattern})`).join("|"), branches };
}

/** scan runs a composed pattern over input and returns what matched, each
 *  hit traced back to the branch it came from. */
export function scan(c: Composed, input: string, max: number): Found[] {
  if (!c.source || !input) return [];
  const out: Found[] = [];
  for (const m of text.scan(input, [{ name: c.name, pattern: c.source }], max)) {
    const found = identify(c, m.match, m.index);
    if (found) out.push(found);
  }
  return out;
}

// identify asks which branch a hit came from by running the branches over
// the hit itself and taking the leftmost, longest of them — the same one
// the composed pattern preferred, since Go's regexp is leftmost-first. It
// also recovers that branch's groups, which is why the composed pattern
// needn't carry any. Picking the leftmost matters: a shadow file's line
// ("root:$6$salt$hash") holds a crypt hash from its sixth character, and it
// is the line, not the hash inside it, that was found.
function identify(c: Composed, match: string, index: number): Found | null {
  const found = text.scan(
    match,
    c.branches.map((b) => ({ name: b.id, pattern: b.pattern })),
    c.branches.length + 8,
  );
  if (found.length === 0) return null;
  let best = found[0];
  for (const m of found) {
    if (m.index < best.index || (m.index === best.index && m.match.length > best.match.length)) best = m;
  }
  return { id: best.pattern, match, groups: best.groups, index };
}
