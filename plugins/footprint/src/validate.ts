// Small checks shared by the detectors: undoing form encoding, pulling the
// digits out of a value, and deciding whether a number could really be a
// telephone number. Copied from the sensitive-info plugin (plugins don't
// import each other), trimmed to what footprint uses.

/** decodeForm undoes form encoding (%xx and +), leaving a bad escape alone. */
export function decodeForm(v: string): string {
  if (v.indexOf("%") < 0 && v.indexOf("+") < 0) return v;
  try {
    return decodeURIComponent(v.replace(/\+/g, " "));
  } catch {
    return v;
  }
}

/** digits returns just the digits of a value: "+1 (415)" -> "1415". */
export function digits(v: string): string {
  return v.replace(/[^0-9]/g, "");
}

/** isPlaceholder reports whether a value is empty, a template hole or a word
 *  that stands in for a real value, so a sample is not recorded as real. */
export function isPlaceholder(v: string): boolean {
  const t = v.trim();
  if (t === "" || t.length > 4096) return true;
  if (/^(?:null|undefined|nil|none|n\/?a|example|sample|your[_-]?[a-z0-9_-]*|placeholder|changeme|test)$/i.test(t)) return true;
  if (/^(?:\{\{.*\}\}|\$\{.*\}|<[^>]*>|%[sdv]|:[a-z_]+|\[[a-z_ ]+\])$/i.test(t)) return true;
  return false;
}

/** plausiblePhone reports whether a value could be a telephone number:
 *  7 to 15 digits, and not a year, a price or an identifier. */
export function plausiblePhone(v: string): boolean {
  const d = digits(v);
  if (d.length < 7 || d.length > 15) return false;
  if (/^0+$/.test(d)) return false;
  // A run of one digit, or a straight count, is test data at best.
  return !/^(\d)\1+$/.test(d) && d !== "1234567890";
}
