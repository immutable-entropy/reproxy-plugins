// Reading CISA's Known Exploited Vulnerabilities catalog (the JSON feed) and
// reducing it to a small index that fits plugin storage.
//
// The raw feed is ~1.8 MiB (1700+ entries); plugin storage is 1 MiB, so the
// feed is never kept whole. Only what a finding needs is kept: a per-CVE
// record (its KEV name and dates, and whether it is used in ransomware), and
// the (vendor, product, cve) triples so a product can be matched. The long
// shortDescription and requiredAction are dropped — the NVD description
// already carries the detail, and the KEV page carries the required action.
//
// KEV has no version information, so a product match means "this product has
// known-exploited CVEs; confirm whether the running version is affected", not
// "this version is vulnerable".

/** A (vendor, product, cve) triple, all lower-cased but the cve. */
export interface KevEntry {
  cve: string;
  vendor: string;
  product: string;
}

/** The per-CVE detail a finding shows. */
export interface KevRecord {
  name: string;
  added: string;
  due: string;
  ransom: boolean;
}

export interface KevIndex {
  entries: KevEntry[];
  byCve: Record<string, KevRecord>;
}

/** The CISA KEV catalog page. */
export function kevPage(): string {
  return "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
}

/** Reduce the KEV feed to the index; undefined when the feed isn't one. */
export function reduceKev(reply: unknown): KevIndex | undefined {
  if (!reply || typeof reply !== "object") return undefined;
  const list = (reply as Record<string, unknown>).vulnerabilities;
  if (!Array.isArray(list)) return undefined;
  const index: KevIndex = { entries: [], byCve: {} };
  for (const v of list) {
    if (!v || typeof v !== "object") continue;
    const r = v as Record<string, unknown>;
    const cve = str(r.cveID);
    if (!cve) continue;
    index.entries.push({ cve, vendor: str(r.vendorProject).toLowerCase(), product: str(r.product).toLowerCase() });
    index.byCve[cve] = {
      name: str(r.vulnerabilityName),
      added: str(r.dateAdded).slice(0, 10),
      due: str(r.dueDate).slice(0, 10),
      ransom: str(r.knownRansomwareCampaignUse).toLowerCase() === "known",
    };
  }
  return index;
}

/** The KEV CVEs for a catalogued product (vendor exact, product keyword contained). */
export function kevForProduct(index: KevIndex, key: { vendor: string; product: string }): string[] {
  const vendor = key.vendor.toLowerCase();
  const product = key.product.toLowerCase();
  const out: string[] = [];
  for (const e of index.entries) {
    if (e.vendor === vendor && e.product.indexOf(product) >= 0 && out.indexOf(e.cve) < 0) out.push(e.cve);
  }
  return out;
}

/** The KEV record for a CVE, when it is in the catalog. */
export function kevRecord(index: KevIndex, cve: string): KevRecord | undefined {
  return index.byCve[cve];
}

function str(v: unknown): string {
  return typeof v === "string" || typeof v === "number" ? String(v).trim() : "";
}
