// Reading the DNS names out of a certificate, for crt.sh, which hands out
// a certificate's whole SAN list only as the certificate itself
// (GET https://crt.sh/?d=<id>, a PEM file). Its JSON search lists just the
// names that matched the query.
//
// This is not an X.509 parser. It finds the subjectAltName extension (OID
// 2.5.29.17) and reads the dNSName entries ([2] IA5String) of the
// GeneralNames sequence inside it, checking every length against the
// bytes there are. Anything that doesn't add up gives no names rather than
// wrong ones.

/** The bytes of the first certificate in a PEM file; undefined if there is none. */
export function pemBody(pem: string): Uint8Array | undefined {
  const m = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----/.exec(pem);
  if (!m) return undefined;
  let bin: string;
  try {
    bin = atob(m[1].replace(/\s+/g, ""));
  } catch {
    return undefined;
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** The OID 2.5.29.17 (subjectAltName), as encoded: tag, length, value. */
const sanOID = [0x06, 0x03, 0x55, 0x1d, 0x11];

/**
 * The dNSName entries of a DER certificate's subjectAltName, in order, or
 * undefined when the certificate has none that can be read.
 */
export function sanDNSNames(der: Uint8Array): string[] | undefined {
  for (let i = indexOf(der, sanOID, 0); i >= 0; i = indexOf(der, sanOID, i + 1)) {
    let p = i + sanOID.length;
    // An optional "critical" BOOLEAN comes before the value.
    if (der[p] === 0x01) {
      const b = tlv(der, p);
      if (!b) continue;
      p = b.end;
    }
    const octets = tlv(der, p);
    if (!octets || octets.tag !== 0x04) continue;
    const seq = tlv(der, octets.start);
    if (!seq || seq.tag !== 0x30 || seq.end > octets.end) continue;
    const names: string[] = [];
    for (let q = seq.start; q < seq.end; ) {
      const gn = tlv(der, q);
      if (!gn || gn.end > seq.end) return undefined;
      if (gn.tag === 0x82) names.push(ascii(der, gn.start, gn.end));
      q = gn.end;
    }
    return names;
  }
  return undefined;
}

interface TLV {
  tag: number;
  start: number;
  end: number;
}

/** The tag-length-value at p, or undefined if its length runs past the data. */
function tlv(b: Uint8Array, p: number): TLV | undefined {
  if (p + 2 > b.length) return undefined;
  const tag = b[p];
  let len = b[p + 1];
  let start = p + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 3 || start + n > b.length) return undefined;
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + b[start + k];
    start += n;
  }
  const end = start + len;
  return end <= b.length ? { tag, start, end } : undefined;
}

function indexOf(b: Uint8Array, needle: number[], from: number): number {
  outer: for (let i = from; i + needle.length <= b.length; i++) {
    for (let k = 0; k < needle.length; k++) if (b[i + k] !== needle[k]) continue outer;
    return i;
  }
  return -1;
}

function ascii(b: Uint8Array, start: number, end: number): string {
  let s = "";
  for (let i = start; i < end; i++) s += String.fromCharCode(b[i]);
  return s;
}
