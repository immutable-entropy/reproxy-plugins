// endpoint-mapper: puts the URLs responses refer to on the Map.
//
// Core already maps the links a page makes to its own host. This plugin
// reads further: URLs inside JSON values, API calls in scripts (fetch,
// axios, XMLHttpRequest), robots.txt and sitemap.xml, and the paths of
// OpenAPI and Swagger documents — on any host one of the targets covers.

import { endpoints, settings, targets, type Hooks } from "reproxy";
import { extract, type Found } from "./src/extract";

export async function mapResponse({ flow }: Hooks["traffic.on_response_received"]): Promise<void> {
  const body = flow.response.text();
  if (!body) return;
  const max = settings.get<number>("max_links_per_response");
  const found = extract(body, flow.url, flow.response.contentType(), {
    max,
    openapi: settings.get<boolean>("openapi"),
  });
  const noTargets = targets.list().length === 0;
  const outOfScope = settings.get<boolean>("include_out_of_scope");

  let added = 0;
  for (const f of found) {
    if (added >= max) break;
    if (!outOfScope && !(noTargets ? sameSite(f.url, flow.url) : targets.match(f.url))) continue;
    if (endpoints.get(f.url)) continue; // already on the map
    await endpoints.add({ url: f.url, flowId: flow.id, detail: f.detail });
    added++;
  }
}

/** sameSite: the hosts share their last two labels (app.corp.test and api.corp.test). */
export function sameSite(a: string, b: string): boolean {
  const site = (u: string) => {
    const host = u.replace(/^[a-z]+:\/\//i, "").split(/[/:?#]/)[0].toLowerCase();
    return host.split(".").slice(-2).join(".");
  };
  return site(a) === site(b);
}

export type { Found };
