// precon: pre-engagement reconnaissance, driven from the command line.
//
// This plugin gathers what is publicly known about a domain before an
// engagement begins — the host names and addresses under it, and the
// certificates issued for it — and adds what it finds to the Entity
// Explorer and Targets → Related. Unlike most plugins it watches no
// traffic and no entities: it does its work only when the user runs one of
// its commands, so nothing happens until it is asked.
//
//   reproxy precon dns <domain>   DNS reconnaissance (DNSDumpster)
//   reproxy precon ssl <domain>   Certificate Transparency (crt.sh, ctlogs.dev)
//
// It replaces the earlier dnsdumpster and certificate-transparency plugins,
// which did the same lookups automatically whenever a domain was added to
// the targets. Driving them from the command line instead means a lookup —
// which sends the domain name to a third party — happens when the tester
// decides it should, not as a side effect of editing the scope.
//
// The parsing those lookups need is already written and carried over from
// the two old plugins: src/dns/records.ts reads DNSDumpster's reply, and
// src/ssl/{certs,der,notes}.ts read and merge the Certificate Transparency
// searches. src/names.ts holds the host and domain helpers both share. The
// command functions below are stubs for now; they will be wired to that
// logic next.

import { type CommandHandler } from "reproxy";

/** The domain argument shared by both commands, lower-cased and trimmed. */
function domainArg(args: string[]): string {
  return String(args[0] ?? "").trim().toLowerCase().replace(/\.$/, "");
}

export const dns: CommandHandler = async ({ args }) => {
  const domain = domainArg(args);
  if (!domain) return { output: "precon dns: give a domain, e.g. reproxy precon dns example.com", code: 2 };
  return { output: `precon dns ${domain}: not built out yet.`, code: 1 };
};

export const ssl: CommandHandler = async ({ args }) => {
  const domain = domainArg(args);
  if (!domain) return { output: "precon ssl: give a domain, e.g. reproxy precon ssl example.com", code: 2 };
  return { output: `precon ssl ${domain}: not built out yet.`, code: 1 };
};
