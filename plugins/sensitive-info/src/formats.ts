// The secrets that carry their own shape: credentials you can recognise
// without knowing what field they came from.
//
// Each rule is one branch of a composed pattern (see pattern.ts), so all of
// them are looked for in a single pass. A rule's value is the whole match;
// what it means is decided by which branch matched.
//
// Nearly every format contains a literal — AKIA, ghp_, -----BEGIN, $2y$ —
// and that literal is the rule's anchor. A cheap indexOf says whether a
// body could hold the format at all, and the pattern is only ever run
// around the places it could be, which is what keeps a 512 KiB body
// affordable (see detectors.ts). A rule with nothing to anchor on, such as
// an email address or a card number, is run over the body itself, up to a
// smaller limit.

import type { Branch } from "./pattern";

/** The finding types this plugin declares (see plugin.json). */
export type FindingType = "credential" | "secret-key" | "token" | "hash" | "personal-data" | "payment-data" | "fingerprint";

export interface Rule {
  id: string;
  label: string;
  type: FindingType;
  pattern: string;
  /** Lower-case literals, any one of which a hit must contain. */
  anchors?: string[];
  /** How much text around an anchor is scanned. The defaults suit a value
   *  on one line; a key or a token that runs for lines needs more. */
  before?: number;
  after?: number;
  /** What the finding's notes say about the risk. */
  note?: string;
}

/**
 * Keys and tokens whose format names the service that issued them. A hit is
 * a real secret nearly every time, so these need no entropy check.
 */
export const KEY_RULES: Rule[] = [
  {
    id: "aws_access_key",
    label: "AWS access key ID",
    type: "secret-key",
    pattern: `\\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\\b`,
    anchors: ["akia", "asia", "abia", "acca"],
  },
  {
    id: "github_token",
    label: "GitHub token",
    type: "secret-key",
    pattern: `\\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\\b`,
    anchors: ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
    after: 600,
  },
  {
    id: "gitlab_token",
    label: "GitLab token",
    type: "secret-key",
    pattern: `\\bgl(?:pat|ptt|rt|soat|ft|dt|cbt|agent)-[A-Za-z0-9_-]{20,64}\\b`,
    anchors: ["glpat-", "glptt-", "glrt-", "glsoat-", "glft-", "gldt-", "glcbt-", "glagent-"],
  },
  {
    id: "slack_token",
    label: "Slack token",
    type: "secret-key",
    pattern: `\\b(?:xox[baprse]-[A-Za-z0-9-]{10,}|xapp-[0-9]-[A-Za-z0-9-]{10,})\\b`,
    anchors: ["xox", "xapp-"],
  },
  {
    id: "slack_webhook",
    label: "Slack webhook URL",
    type: "secret-key",
    pattern: `https://hooks\\.slack\\.com/services/[A-Za-z0-9_/+-]{20,}`,
    anchors: ["hooks.slack.com"],
  },
  {
    id: "discord_webhook",
    label: "Discord webhook URL",
    type: "secret-key",
    pattern: `https://(?:canary\\.|ptb\\.)?discord(?:app)?\\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}`,
    anchors: ["/api/webhooks/"],
    before: 300,
    after: 400,
  },
  {
    id: "stripe_key",
    label: "Stripe secret key",
    type: "secret-key",
    pattern: `\\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\\b`,
    anchors: ["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
  },
  {
    id: "google_api_key",
    label: "Google API key",
    type: "secret-key",
    pattern: `\\bAIza[0-9A-Za-z_-]{35}\\b`,
    anchors: ["aiza"],
  },
  {
    id: "google_oauth_secret",
    label: "Google OAuth client secret",
    type: "secret-key",
    pattern: `\\bGOCSPX-[A-Za-z0-9_-]{20,}\\b`,
    anchors: ["gocspx-"],
  },
  {
    id: "firebase_server_key",
    label: "Firebase server key",
    type: "secret-key",
    pattern: `\\bAAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{130,}\\b`,
    anchors: ["apa91b"],
    before: 60,
    after: 400,
  },
  {
    id: "anthropic_key",
    label: "Anthropic API key",
    type: "secret-key",
    pattern: `\\bsk-ant-[A-Za-z0-9_-]{24,}\\b`,
    anchors: ["sk-ant-"],
    after: 400,
  },
  {
    id: "openai_key",
    label: "OpenAI API key",
    type: "secret-key",
    pattern: `\\b(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,})\\b`,
    anchors: ["sk-"],
    after: 400,
  },
  { id: "npm_token", label: "npm token", type: "secret-key", pattern: `\\bnpm_[A-Za-z0-9]{36}\\b`, anchors: ["npm_"] },
  {
    id: "pypi_token",
    label: "PyPI token",
    type: "secret-key",
    pattern: `\\bpypi-[A-Za-z0-9_-]{50,}\\b`,
    anchors: ["pypi-"],
    after: 400,
  },
  {
    id: "sendgrid_key",
    label: "SendGrid API key",
    type: "secret-key",
    pattern: `\\bSG\\.[A-Za-z0-9_-]{16,32}\\.[A-Za-z0-9_-]{16,64}\\b`,
    anchors: ["sg."],
  },
  {
    id: "mailgun_key",
    label: "Mailgun API key",
    type: "secret-key",
    pattern: `\\bkey-[0-9a-f]{32}\\b`,
    anchors: ["key-"],
  },
  {
    id: "shopify_token",
    label: "Shopify access token",
    type: "secret-key",
    pattern: `\\bshp(?:at|ca|pa|ss)_[0-9a-f]{32}\\b`,
    anchors: ["shpat_", "shpca_", "shppa_", "shpss_"],
  },
  {
    id: "square_token",
    label: "Square access token",
    type: "secret-key",
    pattern: `\\b(?:sq0(?:atp|csp|idp)-[A-Za-z0-9_-]{20,}|EAAA[A-Za-z0-9_-]{56,})\\b`,
    anchors: ["sq0", "eaaa"],
    after: 400,
  },
  {
    id: "digitalocean_token",
    label: "DigitalOcean token",
    type: "secret-key",
    pattern: `\\bdo[oprt]_v1_[0-9a-f]{64}\\b`,
    anchors: ["dop_v1_", "doo_v1_", "dor_v1_", "dot_v1_"],
  },
  {
    id: "telegram_bot_token",
    label: "Telegram bot token",
    type: "secret-key",
    pattern: `\\b[0-9]{8,10}:AA[A-Za-z0-9_-]{32,40}\\b`,
    anchors: [":aa"],
  },
  {
    id: "atlassian_token",
    label: "Atlassian API token",
    type: "secret-key",
    pattern: `\\bAT(?:ATT|CTT)3x[A-Za-z0-9_=-]{50,}`,
    anchors: ["atatt3x", "atctt3x"],
    after: 400,
  },
  {
    id: "dropbox_token",
    label: "Dropbox token",
    type: "secret-key",
    pattern: `\\bsl\\.[A-Za-z0-9_-]{100,}\\b`,
    anchors: ["sl."],
    after: 400,
  },
  { id: "figma_token", label: "Figma token", type: "secret-key", pattern: `\\bfigd_[A-Za-z0-9_-]{30,}\\b`, anchors: ["figd_"] },
  { id: "linear_key", label: "Linear API key", type: "secret-key", pattern: `\\blin_api_[A-Za-z0-9]{40}\\b`, anchors: ["lin_api_"] },
  {
    id: "postman_key",
    label: "Postman API key",
    type: "secret-key",
    pattern: `\\bPMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}\\b`,
    anchors: ["pmak-"],
  },
  {
    id: "new_relic_key",
    label: "New Relic key",
    type: "secret-key",
    pattern: `\\b(?:NRAK-[A-Z0-9]{27}|NRJS-[a-f0-9]{19})\\b`,
    anchors: ["nrak-", "nrjs-"],
  },
  { id: "supabase_key", label: "Supabase service key", type: "secret-key", pattern: `\\bsbp_[a-f0-9]{40}\\b`, anchors: ["sbp_"] },
  {
    id: "doppler_token",
    label: "Doppler token",
    type: "secret-key",
    pattern: `\\bdp\\.(?:pt|st|sa|ct|scim|audit)\\.[A-Za-z0-9]{40,}\\b`,
    anchors: ["dp.pt.", "dp.st.", "dp.sa.", "dp.ct.", "dp.scim.", "dp.audit."],
  },
  {
    id: "vault_token",
    label: "HashiCorp Vault token",
    type: "secret-key",
    pattern: `\\bhv[sb]\\.[A-Za-z0-9_-]{24,}\\b`,
    anchors: ["hvs.", "hvb."],
  },
  { id: "grafana_token", label: "Grafana token", type: "secret-key", pattern: `\\bglc_[A-Za-z0-9+/=]{32,}`, anchors: ["glc_"] },
  {
    id: "jfrog_token",
    label: "JFrog access token",
    type: "secret-key",
    pattern: `\\bcmVmdGtuOjAx[A-Za-z0-9]{60,}`,
    anchors: ["cmvmdgtuojax"],
    after: 600,
  },
  {
    id: "azure_storage_key",
    label: "Azure storage account key",
    type: "secret-key",
    pattern: `(?i:accountkey=)[A-Za-z0-9+/]{64,}={0,2}`,
    anchors: ["accountkey="],
    after: 400,
  },
  {
    id: "private_key",
    label: "Private key",
    type: "secret-key",
    pattern: `-----BEGIN (?:[A-Z0-9 ]{1,24} )?PRIVATE KEY(?: BLOCK)?-----(?s:.*?)-----END (?:[A-Z0-9 ]{1,24} )?PRIVATE KEY(?: BLOCK)?-----`,
    anchors: ["-----begin"],
    before: 60,
    after: 9000,
    note: "A private key belongs on the server that owns it and should never cross the wire.",
  },
  {
    id: "putty_key",
    label: "PuTTY private key",
    type: "secret-key",
    pattern: `PuTTY-User-Key-File-[0-9]:[ \\t]*[^\\r\\n]{1,64}`,
    anchors: ["putty-user-key-file-"],
  },
  {
    id: "jwt",
    label: "JSON Web Token",
    type: "token",
    pattern: `\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{0,683}`,
    anchors: ["eyj"],
    before: 60,
    after: 3000,
    note: "Anyone holding the token can act as whoever it was issued to until it expires.",
  },
  {
    id: "url_credentials",
    label: "Credentials in a URL",
    type: "credential",
    pattern:
      `(?i:(?:https?|ftps?|ssh|sftp|smb|ldaps?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|rediss?|amqps?|mssql|clickhouse|cassandra|kafka|jdbc:[a-z0-9]{2,16})://)` +
      `[A-Za-z0-9._%+~-]{1,64}:[^\\s"'<>@/\\\\]{1,128}@[A-Za-z0-9._-]{1,253}`,
    anchors: ["@"],
    before: 240,
    after: 300,
    note: "A URL with a password in it is logged by every proxy, browser and server it passes.",
  },
];

/**
 * Stored password hashes and digests. A hash is not a password, but it is
 * enough to crack offline, and for some schemes enough to replay as it is
 * (NTLM), so it should never reach a client.
 */
export const HASH_RULES: Rule[] = [
  {
    id: "bcrypt_hash",
    label: "bcrypt hash",
    type: "hash",
    pattern: `\\$2[abxy]?\\$[0-9]{2}\\$[./A-Za-z0-9]{53}`,
    anchors: ["$2"],
  },
  {
    id: "argon2_hash",
    label: "Argon2 hash",
    type: "hash",
    pattern: `\\$argon2(?:id|i|d)\\$[A-Za-z0-9$,=+/.-]{20,200}`,
    anchors: ["$argon2"],
    after: 400,
  },
  {
    id: "crypt_hash",
    label: "crypt(3) hash",
    type: "hash",
    pattern: `\\$(?:1|5|6|y|sha1)\\$(?:rounds=[0-9]{3,9}\\$)?[./A-Za-z0-9]{0,22}\\$[./A-Za-z0-9]{20,110}`,
    anchors: ["$1$", "$5$", "$6$", "$y$", "$sha1$"],
    after: 400,
  },
  {
    id: "apr1_hash",
    label: "Apache apr1 hash",
    type: "hash",
    pattern: `\\$apr1\\$[./A-Za-z0-9]{0,8}\\$[./A-Za-z0-9]{22}`,
    anchors: ["$apr1$"],
  },
  { id: "phpass_hash", label: "phpass hash", type: "hash", pattern: `\\$[PH]\\$[./A-Za-z0-9]{31}`, anchors: ["$p$", "$h$"] },
  {
    id: "framework_hash",
    label: "Password hash",
    type: "hash",
    pattern: `(?:pbkdf2_sha256|pbkdf2_sha1|pbkdf2|bcrypt_sha256|scrypt|argon2)\\$[0-9]+\\$[A-Za-z0-9+/=._-]{1,64}\\$[A-Za-z0-9+/=]{20,100}`,
    anchors: ["pbkdf2", "bcrypt_sha256", "scrypt", "argon2"],
    after: 400,
  },
  {
    id: "ldap_hash",
    label: "LDAP password hash",
    type: "hash",
    pattern: `\\{(?:SSHA256|SSHA512|SSHA|SHA|SMD5|MD5|CRYPT)\\}[A-Za-z0-9+/=]{10,200}`,
    anchors: ["{ssha", "{sha", "{md5", "{smd5", "{crypt"],
    after: 400,
  },
  {
    id: "shadow_line",
    label: "Password file entry",
    type: "hash",
    pattern: `(?m)^[A-Za-z0-9._-]{1,32}:\\$[0-9a-z]{1,8}\\$[^\\s:]{10,120}`,
    anchors: [":$"],
    before: 100,
    after: 400,
    note: "A line of a shadow or htpasswd file: a user name and the hash of their password.",
  },
  // No anchor: a hash is only digits and letters, so these are run over the
  // body itself (and are small patterns for that reason).
  { id: "mysql_hash", label: "MySQL password hash", type: "hash", pattern: `\\*[0-9A-F]{40}\\b` },
  {
    id: "ntlm_pair",
    label: "LM/NTLM hash pair",
    type: "hash",
    pattern: `\\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\\b`,
    note: "An NTLM hash is a credential in itself: it can be replayed without being cracked.",
  },
];

/** Bare hex digests, which only a setting turns on: too much of the web is
 *  32 hex characters for this to be quiet. */
export const HEX_HASH_RULE: Rule = {
  id: "hex_hash",
  label: "Hash",
  type: "hash",
  pattern: `\\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})\\b`,
};

/** Personal data: what identifies a person rather than authenticates them.
 *  None of it has a literal to anchor on, and each is checked before it is
 *  reported (see validate.ts). */
export const PII_RULES: Rule[] = [
  {
    id: "email",
    label: "Email address",
    type: "personal-data",
    pattern: `\\b[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9-]{1,63}(?:\\.[A-Za-z0-9-]{1,63}){0,8}\\.[A-Za-z]{2,24}\\b`,
  },
  {
    id: "credit_card",
    label: "Payment card number",
    type: "payment-data",
    pattern: `\\b(?:4[0-9]{3}|5[1-5][0-9]{2}|2[2-7][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}|22[0-9])|3(?:0[0-5][0-9]|[68][0-9]{2}))(?:[ -]?[0-9]{4}){2}[ -]?[0-9]{1,7}\\b`,
    note: "Card numbers in traffic put the application in scope for PCI DSS.",
  },
  { id: "ssn", label: "US Social Security number", type: "personal-data", pattern: `\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b` },
  {
    id: "iban",
    label: "IBAN",
    type: "payment-data",
    pattern: `\\b[A-Z]{2}[0-9]{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\\b`,
  },
  { id: "phone", label: "Telephone number", type: "personal-data", pattern: `\\+[1-9][0-9]{7,14}\\b` },
  { id: "uk_nino", label: "UK National Insurance number", type: "personal-data", pattern: `\\b[A-CEGHJ-PR-TW-Z]{2}[0-9]{6}[A-D]\\b` },
];

/** Credentials carried in a message's own headers. The head of a message is
 *  small, so these are run over all of it. */
export const HEADER_RULES: Rule[] = [
  {
    id: "auth_header",
    label: "Authorization credential",
    type: "token",
    // the scheme, then the credential: "Authorization: Basic dXNlcjpwYXNz".
    pattern: `(?im)^(?:proxy-)?authorization:[ \\t]*([A-Za-z][A-Za-z0-9._~+/-]{1,24})[ \\t]+([^\\r\\n]{4,})`,
    anchors: ["authorization:"],
  },
  {
    id: "auth_header_bare",
    label: "Authorization credential",
    type: "token",
    // Some APIs send the credential with no scheme at all.
    pattern: `(?im)^(?:proxy-)?authorization:[ \\t]*([A-Za-z0-9._~+/=-]{16,})[ \\t]*$`,
    anchors: ["authorization:"],
  },
];

// The personal data worth masking on screen. An identifier a person can't
// change — a Social Security number, a national insurance number, a
// passport number — does as much harm read over a shoulder as a password
// does; an email address, a telephone number or a date of birth is
// sensitive but not secret, and masking it would only hide what the tester
// is looking at.
const MASKED_PII = ["ssn", "uk_nino", "field_gov_id"];

/**
 * isSecret reports whether a finding's value should reach the user masked
 * (reProxy hides it behind the eye beside the value). Everything that
 * authenticates — a password, a key, a token, a hash, a card — is masked;
 * personal data only when it is an identifier of its own; a disclosure of
 * the stack (fingerprint.ts) never.
 */
export function isSecret(type: FindingType, detector: string): boolean {
  // What a site runs on is something to hide from attackers, not from the
  // tester's screen.
  if (type === "fingerprint") return false;
  if (type === "personal-data") return MASKED_PII.indexOf(detector) >= 0;
  return true;
}

/** branches turns rules into the branches of a composed pattern. */
export function branches(rules: Rule[]): Branch[] {
  return rules.map((r) => ({ id: r.id, pattern: r.pattern }));
}

/** byId indexes rules for the classification that follows a match. */
export function byId(rules: Rule[]): Record<string, Rule> {
  const out: Record<string, Rule> = {};
  for (const r of rules) out[r.id] = r;
  return out;
}
