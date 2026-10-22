// Which disclosed products can be looked up, and how. NVD is queried by a
// CPE "part:vendor:product" (the version is added per query); CISA KEV is
// matched by a vendor and a product keyword, because KEV's product names
// vary ("BIG-IP", "BIG-IP APM", "Confluence Data Center and Server").
//
// Each CPE "vendor:product" here was checked against the live NVD API: the
// vendor is not always the obvious one (nginx is F5's now). A product with a
// CPE is looked up version-precise on NVD. A product with only a KEV entry
// (F5 BIG-IP, Confluence — no single, version-matchable CPE product) is
// reported from KEV at the product level, with a note to confirm the running
// version. An unmapped product is never queried: a guessed CPE finds nothing
// or the wrong thing.

export interface KevKey {
  /** The KEV vendorProject, lower-cased, matched exactly. */
  vendor: string;
  /** A substring of the KEV product name, lower-cased (big-ip matches "BIG-IP APM"). */
  product: string;
}

export interface Mapping {
  /** How the product is named in a finding. */
  name: string;
  /** Banner product tokens (lower case) that map here. */
  aliases: string[];
  /** The NVD CPE "part:vendor:product", when the product has a single one. */
  cpe?: string;
  /** The CISA KEV vendor + product keyword, for a product-level match. */
  kev?: KevKey;
}

export const CATALOG: Mapping[] = [
  { name: "Apache HTTP Server", aliases: ["apache"], cpe: "a:apache:http_server" },
  { name: "nginx", aliases: ["nginx"], cpe: "a:f5:nginx" },
  { name: "OpenResty", aliases: ["openresty"], cpe: "a:openresty:openresty" },
  { name: "lighttpd", aliases: ["lighttpd"], cpe: "a:lighttpd:lighttpd" },
  { name: "Apache Tomcat", aliases: ["tomcat"], cpe: "a:apache:tomcat" },
  { name: "PHP", aliases: ["php"], cpe: "a:php:php" },
  { name: "OpenSSL", aliases: ["openssl"], cpe: "a:openssl:openssl" },
  { name: "OpenSSH", aliases: ["openssh"], cpe: "a:openbsd:openssh" },
  { name: "Drupal", aliases: ["drupal"], cpe: "a:drupal:drupal" },
  { name: "Jenkins", aliases: ["jenkins"], cpe: "a:jenkins:jenkins" },
  { name: "GitLab", aliases: ["gitlab"], cpe: "a:gitlab:gitlab" },
  { name: "Atlassian Jira", aliases: ["jira"], cpe: "a:atlassian:jira", kev: { vendor: "atlassian", product: "jira" } },
  // Confluence's CVEs are split over several CPE products, so it is matched
  // by KEV at the product level rather than queried version-precise on NVD.
  { name: "Atlassian Confluence", aliases: ["confluence"], kev: { vendor: "atlassian", product: "confluence" } },
  // F5 BIG-IP is split into a CPE product per module, so there is no single
  // one to version-match; KEV covers it at the product level.
  { name: "F5 BIG-IP", aliases: ["bigip", "big-ip"], kev: { vendor: "f5", product: "big-ip" } },
];

/** The catalog entry a disclosed product token maps to, or undefined. */
export function lookup(product: string): Mapping | undefined {
  const p = product.toLowerCase();
  for (const m of CATALOG) if (m.aliases.indexOf(p) >= 0) return m;
  return undefined;
}
