// Classifying a URL as part of an organisation's external footprint: a
// social-media account, a source-code repository, a cloud storage bucket, a
// package registry entry, or an API/documentation endpoint.
//
// Everything here is pure string work on one URL at a time, so it can be
// unit-tested with no fixtures. main.ts gathers the URLs a response refers
// to with text.urls (which runs in Go) and asks classify() about each one;
// the few that classify are the only ones that go any further (context.ts,
// then a finding).

/** The finding types footprint declares (see plugin.json). */
export type FindingType = "contact" | "social-account" | "source-repo" | "cloud-storage" | "package" | "api-endpoint" | "service-id";

/** A classified URL. kind is set for social and source links, which context.ts
 *  grades further (a profile page vs a deep content link). */
export interface Hit {
  type: FindingType;
  /** The detector id (the platform or asset kind). */
  detector: string;
  /** The label a finding shows. */
  label: string;
  /** The finding's value: a canonical URL or handle. */
  value: string;
  /** "profile" (the account's own page) or "content" (a post, a file). */
  kind?: "profile" | "content";
  note?: string;
  fields?: Record<string, string>;
}

interface Parsed {
  host: string;
  /** The path without its leading slash, lower cased only where noted. */
  path: string;
  /** The non-empty path segments. */
  segs: string[];
  query: string;
}

/** parseUrl breaks an absolute http(s) URL into host, path and query, or
 *  returns null when it isn't one. Userinfo and port are dropped from host. */
export function parseUrl(url: string): Parsed | null {
  const m = /^https?:\/\/([^/?#]+)([^?#]*)(?:\?([^#]*))?/i.exec(url);
  if (!m) return null;
  let host = m[1].toLowerCase();
  const at = host.lastIndexOf("@");
  if (at >= 0) host = host.slice(at + 1);
  host = host.replace(/:\d+$/, "");
  const path = (m[2] || "").replace(/^\/+/, "");
  const segs = path.split("/").filter((s) => s.length > 0);
  return { host, path, segs, query: m[3] || "" };
}

/** hostIs reports whether host is exactly h or a subdomain of it. */
function hostIs(host: string, h: string): boolean {
  return host === h || host.endsWith("." + h);
}

// ---- Social media ------------------------------------------------------------

interface Social {
  id: string;
  name: string;
  hosts: string[];
  /** Path first segments that are the platform's own, not an account. */
  reserved?: string[];
  /** Decide the handle and whether a path is a profile or a content link. */
  classify?: (p: Parsed) => { handle: string; kind: "profile" | "content" } | null;
}

/** A handle from the first path segment, a profile when that is all there is. */
function firstSegment(p: Parsed, reserved: string[] = []): { handle: string; kind: "profile" | "content" } | null {
  let seg = p.segs[0];
  if (!seg) return null; // the platform's home page, not an account
  if (seg[0] === "@") seg = seg.slice(1);
  if (!seg || reserved.indexOf(seg.toLowerCase()) >= 0) return null;
  return { handle: seg, kind: p.segs.length <= 1 ? "profile" : "content" };
}

const SOCIAL: Social[] = [
  { id: "facebook", name: "Facebook", hosts: ["facebook.com", "fb.com", "fb.me"], reserved: ["sharer", "sharer.php", "share.php", "dialog", "plugins", "tr", "login", "events", "watch"] },
  {
    id: "twitter",
    name: "X (Twitter)",
    hosts: ["twitter.com", "x.com"],
    reserved: ["intent", "share", "home", "hashtag", "search", "i", "explore", "messages", "notifications", "settings"],
    classify: (p) => {
      const r = firstSegment(p, ["intent", "share", "home", "hashtag", "search", "i", "explore", "messages", "notifications", "settings"]);
      if (r && p.segs.length >= 3 && p.segs[1] === "status") r.kind = "content";
      return r;
    },
  },
  {
    id: "linkedin",
    name: "LinkedIn",
    hosts: ["linkedin.com", "lnkd.in"],
    classify: (p) => {
      const kind = p.segs[0];
      if (kind === "company" || kind === "school" || kind === "in" || kind === "showcase") {
        return p.segs[1] ? { handle: `${kind}/${p.segs[1]}`, kind: "profile" } : null;
      }
      if (kind === "posts" || kind === "pulse" || kind === "feed") return p.segs[1] ? { handle: p.path, kind: "content" } : null;
      return null;
    },
  },
  { id: "instagram", name: "Instagram", hosts: ["instagram.com"], reserved: ["p", "reel", "reels", "explore", "stories", "tv", "accounts"] },
  {
    id: "youtube",
    name: "YouTube",
    hosts: ["youtube.com", "youtu.be"],
    classify: (p) => {
      if (hostIs(p.host, "youtu.be")) return p.segs[0] ? { handle: p.path, kind: "content" } : null;
      const kind = p.segs[0] || "";
      if (kind[0] === "@") return { handle: kind, kind: "profile" };
      if (kind === "channel" || kind === "c" || kind === "user") return p.segs[1] ? { handle: `${kind}/${p.segs[1]}`, kind: "profile" } : null;
      if (kind === "watch" || kind === "shorts" || kind === "playlist" || kind === "embed") return { handle: p.path + (p.query ? "?" + p.query : ""), kind: "content" };
      return null;
    },
  },
  {
    id: "tiktok",
    name: "TikTok",
    hosts: ["tiktok.com"],
    classify: (p) => {
      if (!p.segs[0] || p.segs[0][0] !== "@") return null;
      return { handle: p.segs[0], kind: p.segs.length >= 3 && p.segs[1] === "video" ? "content" : "profile" };
    },
  },
  {
    id: "telegram",
    name: "Telegram",
    hosts: ["t.me", "telegram.me"],
    classify: (p) => {
      const seg = p.segs[0];
      if (!seg) return null;
      if (seg === "joinchat" || seg[0] === "+") return { handle: p.path, kind: "profile" };
      if (["share", "iv", "s"].indexOf(seg) >= 0) return null;
      return { handle: seg, kind: p.segs.length <= 1 ? "profile" : "content" };
    },
  },
  { id: "whatsapp", name: "WhatsApp", hosts: ["wa.me", "api.whatsapp.com"], classify: (p) => ({ handle: p.segs[0] || p.query, kind: "profile" }) },
  { id: "reddit", name: "Reddit", hosts: ["reddit.com"], classify: (p) => {
    const kind = p.segs[0];
    if (kind === "r" || kind === "user" || kind === "u") return p.segs[1] ? { handle: `${kind}/${p.segs[1]}`, kind: p.segs.indexOf("comments") >= 0 ? "content" : "profile" } : null;
    return null;
  } },
  { id: "mastodon", name: "Mastodon", hosts: ["mastodon.social", "mas.to", "fosstodon.org", "hachyderm.io", "infosec.exchange"], classify: (p) => (p.segs[0] && p.segs[0][0] === "@" ? { handle: p.segs[0], kind: p.segs.length <= 1 ? "profile" : "content" } : null) },
  { id: "bluesky", name: "Bluesky", hosts: ["bsky.app"], classify: (p) => (p.segs[0] === "profile" && p.segs[1] ? { handle: p.segs[1], kind: p.segs.indexOf("post") >= 0 ? "content" : "profile" } : null) },
  { id: "threads", name: "Threads", hosts: ["threads.net"], reserved: ["search", "settings"] },
  { id: "discord", name: "Discord invite", hosts: ["discord.gg", "discord.com", "discordapp.com"], classify: (p) => {
    if (hostIs(p.host, "discord.gg")) return p.segs[0] ? { handle: p.segs[0], kind: "profile" } : null;
    return p.segs[0] === "invite" && p.segs[1] ? { handle: p.segs[1], kind: "profile" } : null;
  } },
  { id: "vimeo", name: "Vimeo", hosts: ["vimeo.com"], reserved: ["features", "upgrade", "ondemand", "search"] },
  { id: "twitch", name: "Twitch", hosts: ["twitch.tv"], reserved: ["videos", "directory", "settings", "downloads", "p"] },
  { id: "medium", name: "Medium", hosts: ["medium.com"], classify: (p) => (p.segs[0] && p.segs[0][0] === "@" ? { handle: p.segs[0], kind: p.segs.length <= 1 ? "profile" : "content" } : null) },
  { id: "pinterest", name: "Pinterest", hosts: ["pinterest.com"], reserved: ["pin", "search", "ideas"] },
  { id: "tumblr", name: "Tumblr", hosts: ["tumblr.com"], reserved: ["explore", "search", "dashboard"] },
  { id: "snapchat", name: "Snapchat", hosts: ["snapchat.com"], classify: (p) => (p.segs[0] === "add" && p.segs[1] ? { handle: p.segs[1], kind: "profile" } : null) },
  { id: "vk", name: "VK", hosts: ["vk.com"], reserved: ["share.php", "feed", "search"] },
  { id: "xing", name: "XING", hosts: ["xing.com"], reserved: ["jobs", "search"] },
];

// ---- Source code -------------------------------------------------------------

interface Code {
  id: string;
  name: string;
  hosts: string[];
  reserved: string[];
}

const CODE: Code[] = [
  { id: "github", name: "GitHub", hosts: ["github.com"], reserved: ["features", "about", "pricing", "marketplace", "sponsors", "login", "join", "settings", "topics", "explore", "orgs", "users", "apps", "notifications", "search", "contact", "security", "readme", "customer-stories", "collections", "trending", "enterprise", "team", "nonprofit", "sponsors"] },
  { id: "gitlab", name: "GitLab", hosts: ["gitlab.com"], reserved: ["explore", "users", "help", "dashboard", "-", "search", "public", "groups"] },
  { id: "bitbucket", name: "Bitbucket", hosts: ["bitbucket.org"], reserved: ["product", "account", "dashboard", "repo", "search"] },
  { id: "codeberg", name: "Codeberg", hosts: ["codeberg.org"], reserved: ["explore", "issues", "pulls", "notifications", "user"] },
  { id: "gitea", name: "Gitea", hosts: ["gitea.com"], reserved: ["explore", "issues", "pulls", "notifications", "user"] },
  { id: "sourceforge", name: "SourceForge", hosts: ["sourceforge.net"], reserved: ["directory", "user", "p"] },
  { id: "azure_devops", name: "Azure DevOps", hosts: ["dev.azure.com", "visualstudio.com"], reserved: [] },
  { id: "gitee", name: "Gitee", hosts: ["gitee.com"], reserved: ["explore", "enterprises"] },
  { id: "sourcehut", name: "SourceHut", hosts: ["sr.ht", "git.sr.ht"], reserved: [] },
  { id: "launchpad", name: "Launchpad", hosts: ["launchpad.net"], reserved: ["people"] },
];

/** A source-code repository or owner: one segment is the owner, two the repo. */
function codeLink(p: Parsed, c: Code): Hit | null {
  const owner = p.segs[0];
  if (!owner || c.reserved.indexOf(owner.toLowerCase()) >= 0) return null;
  const repo = p.segs[1];
  // The owner/repo pair, or just the owner's page.
  const handle = repo ? `${owner}/${repo}` : owner;
  const kind = p.segs.length <= 2 ? "profile" : "content";
  return {
    type: "source-repo",
    detector: c.id,
    label: repo ? `${c.name} repository` : `${c.name} account`,
    value: `https://${p.host}/${handle}`,
    kind,
    fields: { platform: c.name, owner, ...(repo ? { repository: repo } : {}) },
  };
}

// ---- Cloud storage -----------------------------------------------------------

/** A cloud storage bucket, by its host (and sometimes the first path segment). */
function bucket(p: Parsed): Hit | null {
  const mk = (provider: string, name: string): Hit => ({
    type: "cloud-storage",
    detector: "bucket",
    label: `${provider} bucket`,
    value: name,
    note: "A storage bucket named in a response is worth checking for public listing and world-readable objects.",
    fields: { provider, bucket: name },
  });
  let m: RegExpExecArray | null;
  // AWS S3: <bucket>.s3[.-]<region>.amazonaws.com, or s3[.-]<region>.amazonaws.com/<bucket>.
  if ((m = /^(.+)\.s3[.-][a-z0-9-]*\.?amazonaws\.com$/.exec(p.host))) return mk("AWS S3", m[1]);
  if (/^s3[.-][a-z0-9-]*\.?amazonaws\.com$/.test(p.host) || p.host === "s3.amazonaws.com") return p.segs[0] ? mk("AWS S3", p.segs[0]) : null;
  // Google Cloud Storage.
  if ((m = /^(.+)\.storage\.googleapis\.com$/.exec(p.host))) return mk("Google Cloud Storage", m[1]);
  if (p.host === "storage.googleapis.com" || p.host === "storage.cloud.google.com") return p.segs[0] ? mk("Google Cloud Storage", p.segs[0]) : null;
  // Azure Blob Storage.
  if ((m = /^(.+)\.blob\.core\.windows\.net$/.exec(p.host))) return mk("Azure Blob Storage", m[1] + (p.segs[0] ? "/" + p.segs[0] : ""));
  // Cloudflare R2.
  if ((m = /^(.+)\.r2\.cloudflarestorage\.com$/.exec(p.host))) return mk("Cloudflare R2", m[1] + (p.segs[0] ? "/" + p.segs[0] : ""));
  // DigitalOcean Spaces.
  if ((m = /^(.+)\.[a-z0-9-]+\.digitaloceanspaces\.com$/.exec(p.host))) return mk("DigitalOcean Spaces", m[1]);
  if (/^[a-z0-9-]+\.digitaloceanspaces\.com$/.test(p.host)) return p.segs[0] ? mk("DigitalOcean Spaces", p.segs[0]) : null;
  // Alibaba OSS.
  if ((m = /^(.+)\.oss-[a-z0-9-]+\.aliyuncs\.com$/.exec(p.host))) return mk("Alibaba OSS", m[1]);
  return null;
}

// ---- Package registries ------------------------------------------------------

interface Registry {
  id: string;
  name: string;
  hosts: string[];
  /** The path prefix a package sits under, and how many segments name it. */
  prefix: string[];
  nameSegs: number;
}

const REGISTRIES: Registry[] = [
  { id: "npm", name: "npm", hosts: ["npmjs.com", "npmjs.org"], prefix: ["package"], nameSegs: 1 },
  { id: "pypi", name: "PyPI", hosts: ["pypi.org"], prefix: ["project"], nameSegs: 1 },
  { id: "rubygems", name: "RubyGems", hosts: ["rubygems.org"], prefix: ["gems"], nameSegs: 1 },
  { id: "packagist", name: "Packagist", hosts: ["packagist.org"], prefix: ["packages"], nameSegs: 2 },
  { id: "crates", name: "crates.io", hosts: ["crates.io"], prefix: ["crates"], nameSegs: 1 },
  { id: "nuget", name: "NuGet", hosts: ["nuget.org"], prefix: ["packages"], nameSegs: 1 },
  { id: "dockerhub", name: "Docker Hub", hosts: ["hub.docker.com"], prefix: ["r"], nameSegs: 2 },
  { id: "maven", name: "Maven Central", hosts: ["mvnrepository.com"], prefix: ["artifact"], nameSegs: 2 },
];

function registry(p: Parsed): Hit | null {
  for (const r of REGISTRIES) {
    if (!r.hosts.some((h) => hostIs(p.host, h))) continue;
    if (r.prefix.length && p.segs[0] !== r.prefix[0]) continue;
    const start = r.prefix.length;
    // A scoped npm package (@scope/name) names itself in two segments.
    const want = r.nameSegs === 1 && (p.segs[start] ?? "").startsWith("@") ? 2 : r.nameSegs;
    const parts = p.segs.slice(start, start + want).filter((s) => s.length > 0);
    if (parts.length < want) return null;
    const name = parts.join("/");
    return {
      type: "package",
      detector: r.id,
      label: `${r.name} package`,
      value: `${r.name}:${name}`,
      fields: { registry: r.name, package: name, url: `https://${p.host}/${p.segs.join("/")}` },
    };
  }
  // ghcr.io/<owner>/<image>: an OCI image, no fixed path prefix.
  if (hostIs(p.host, "ghcr.io") && p.segs.length >= 2) {
    return { type: "package", detector: "ghcr", label: "Container image (GHCR)", value: `ghcr.io/${p.segs.join("/")}`, fields: { registry: "GitHub Container Registry", image: p.segs.join("/") } };
  }
  return null;
}

// ---- API and documentation endpoints ----------------------------------------

/** Paths that mark an API, a GraphQL endpoint or an API-documentation UI. */
const API_MARKERS: { id: string; label: string; re: RegExp }[] = [
  { id: "graphql", label: "GraphQL endpoint", re: /(?:^|\/)(?:graphql|graphiql|___graphql)(?:$|[/?])/i },
  { id: "openapi", label: "OpenAPI/Swagger definition", re: /(?:openapi\.(?:json|ya?ml)|swagger\.(?:json|ya?ml)|\/v[0-9]+\/api-docs|\/api-docs(?:$|[/?.]))/i },
  { id: "swagger_ui", label: "Swagger UI", re: /(?:swagger-ui|\/swagger(?:$|[/?])|\/redoc(?:$|[/?])|\/rapidoc)/i },
  { id: "graphql_playground", label: "GraphQL playground", re: /(?:\/playground(?:$|[/?])|altair)/i },
];

function apiEndpoint(p: Parsed): Hit | null {
  if (hostIs(p.host, "documenter.getpostman.com") || p.host.endsWith(".postman.co")) {
    return { type: "api-endpoint", detector: "postman", label: "Postman documentation", value: `https://${p.host}/${p.segs.join("/")}`, fields: { kind: "Postman" } };
  }
  const full = "/" + p.path + (p.query ? "?" + p.query : "");
  for (const m of API_MARKERS) {
    if (m.re.test(full)) {
      return { type: "api-endpoint", detector: m.id, label: m.label, value: `https://${p.host}${full.split("?")[0]}`, note: "An API or its documentation widens the attack surface worth testing.", fields: { kind: m.label } };
    }
  }
  return null;
}

/**
 * classify decides what a URL is part of the footprint, or returns null. The
 * order is deliberate: a known platform host is read as that platform before
 * its path is checked for an API marker, so github.com/org/graphql-repo is a
 * repository, not a GraphQL endpoint.
 */
export function classify(url: string): Hit | null {
  const p = parseUrl(url);
  if (!p) return null;

  for (const s of SOCIAL) {
    if (!s.hosts.some((h) => hostIs(p.host, h))) continue;
    const r = s.classify ? s.classify(p) : firstSegment(p, s.reserved);
    if (!r) return null;
    // A profile's value is its canonical account URL, so every link to the
    // account merges into one finding; a content link keeps its own URL.
    const canonical = r.handle.indexOf("http") === 0 ? r.handle : `https://${p.host}/${r.handle.replace(/^\//, "")}`;
    return {
      type: "social-account",
      detector: s.id,
      label: `${s.name} ${r.kind === "profile" ? "account" : "link"}`,
      value: r.kind === "profile" ? canonical : url,
      kind: r.kind,
      fields: { platform: s.name, handle: r.handle },
    };
  }
  for (const c of CODE) {
    if (c.hosts.some((h) => hostIs(p.host, h))) return codeLink(p, c);
  }
  return bucket(p) ?? registry(p) ?? apiEndpoint(p);
}
