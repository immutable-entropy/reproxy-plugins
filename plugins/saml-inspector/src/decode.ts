// Finding and decoding the SAML blobs in a message.
//
// SAML is carried base64-encoded. In a POST body (SAMLRequest/SAMLResponse
// form fields) it is plain base64 of the XML. In a redirect URL query it is
// base64 of raw-DEFLATE-compressed XML (the "Redirect" binding). Some flows
// carry the XML directly (SOAP/ECP). This module normalises all of them to
// XML text.

import { text } from "reproxy";

export type SamlKind = "SAMLResponse" | "SAMLRequest" | "assertion" | "xml";
export type Binding = "post" | "redirect" | "xml";

export interface SamlBlob {
  kind: SamlKind;
  binding: Binding;
  /** The raw encoded value as found (for POST/redirect), or the XML itself. */
  raw: string;
  /** Where it was found, for the finding detail. */
  where: string;
}

/** findSamlBlobs locates the SAML payloads in a URL and body text. */
export function findSamlBlobs(url: string, body: string): SamlBlob[] {
  const out: SamlBlob[] = [];

  // Redirect binding: ?SAMLRequest=...&... or ?SAMLResponse=...
  for (const name of ["SAMLResponse", "SAMLRequest"] as const) {
    const q = new RegExp(`[?&]${name}=([^&\\s"']+)`).exec(url);
    if (q) out.push({ kind: name, binding: "redirect", raw: decodeURIComponent(q[1]), where: `${name} query parameter` });
  }

  // POST binding: SAMLResponse / SAMLRequest as a urlencoded form field
  // (name=value at the start of, or anywhere in, a body) or as an HTML
  // form's hidden input (name="..." value="...").
  for (const name of ["SAMLResponse", "SAMLRequest"] as const) {
    if (out.some((b) => b.kind === name)) continue; // already found in the URL
    const field = new RegExp(`(?:^|[?&\\s])${name}=([A-Za-z0-9+/=%]{16,})`).exec(body);
    const input = new RegExp(`name=["']?${name}["']?[^>]*?\\bvalue=["']([A-Za-z0-9+/=%\\s]{16,})["']`, "i").exec(body);
    const hit = input || field;
    if (hit) {
      out.push({ kind: name, binding: "post", raw: decodeURIComponent(hit[1].replace(/\s+/g, "")), where: `${name} form field` });
    }
  }

  // Raw XML: a SOAP/ECP body or a response that is the assertion itself.
  if (/<(?:[A-Za-z][\w.-]*:)?(?:Assertion|Response|AuthnRequest|LogoutRequest)\b/.test(body)) {
    out.push({ kind: "xml", binding: "xml", raw: body, where: "XML body" });
  }
  return out;
}

/** decodeSaml turns a blob into XML text, or "" if it can't. */
export function decodeSaml(blob: SamlBlob): string {
  if (blob.binding === "xml") return blob.raw;
  const bytes = fromBase64(blob.raw);
  if (!bytes) return "";
  if (blob.binding === "post") {
    const xml = utf8(bytes);
    return looksLikeXML(xml) ? xml : "";
  }
  // Redirect: raw DEFLATE. The SDK has no inflate, so ask the host to try
  // both the raw bytes (already XML, some IdPs don't compress) and a
  // DEFLATE decode via text.scan is not possible — fall back to raw.
  const asIs = utf8(bytes);
  if (looksLikeXML(asIs)) return asIs;
  const inflated = inflateRaw(bytes);
  return inflated && looksLikeXML(inflated) ? inflated : "";
}

function looksLikeXML(s: string): boolean {
  return /<(?:[A-Za-z][\w.-]*:)?(?:Assertion|Response|AuthnRequest|LogoutRequest)\b/.test(s);
}

/** fromBase64 decodes standard or URL-safe base64 to bytes. */
export function fromBase64(s: string): Uint8Array | null {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  while (b64.length % 4) b64 += "=";
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function utf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder().decode(bytes);
  } catch {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return s;
  }
}

/**
 * inflateRaw decodes raw DEFLATE (no zlib header), as the SAML Redirect
 * binding uses. A compact pure-TS inflater — enough for the small XML SAML
 * carries.
 */
export function inflateRaw(data: Uint8Array): string {
  try {
    return utf8(rawInflate(data));
  } catch {
    return "";
  }
}

// ---- A small raw-DEFLATE inflater (RFC 1951) --------------------------------

function rawInflate(input: Uint8Array): Uint8Array {
  const out: number[] = [];
  let pos = 0;
  let bitBuf = 0;
  let bitCnt = 0;

  const getBit = (): number => {
    if (bitCnt === 0) {
      bitBuf = input[pos++];
      bitCnt = 8;
    }
    const b = bitBuf & 1;
    bitBuf >>= 1;
    bitCnt--;
    return b;
  };
  const getBits = (n: number): number => {
    let v = 0;
    for (let i = 0; i < n; i++) v |= getBit() << i;
    return v;
  };

  const buildTree = (lengths: number[]) => {
    const max = Math.max(...lengths, 0);
    const blCount = new Array(max + 1).fill(0);
    for (const l of lengths) if (l) blCount[l]++;
    const next = new Array(max + 1).fill(0);
    let code = 0;
    for (let bits = 1; bits <= max; bits++) {
      code = (code + blCount[bits - 1]) << 1;
      next[bits] = code;
    }
    const codes: Record<number, number> = {};
    lengths.forEach((len, sym) => {
      if (len) codes[(len << 16) | next[len]++] = sym;
    });
    return { codes, max };
  };

  const decodeSym = (tree: { codes: Record<number, number>; max: number }): number => {
    let code = 0;
    for (let len = 1; len <= tree.max; len++) {
      code = (code << 1) | getBit();
      const sym = tree.codes[(len << 16) | code];
      if (sym !== undefined) return sym;
    }
    throw new Error("bad code");
  };

  const lenBase = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
  const lenExtra = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
  const distBase = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
  const distExtra = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

  for (;;) {
    const last = getBit();
    const type = getBits(2);
    if (type === 0) {
      bitCnt = 0;
      const len = input[pos] | (input[pos + 1] << 8);
      pos += 4;
      for (let i = 0; i < len; i++) out.push(input[pos++]);
    } else {
      let litTree, distTree;
      if (type === 1) {
        const litLen = new Array(288).fill(0).map((_, i) => (i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8));
        litTree = buildTree(litLen);
        distTree = buildTree(new Array(30).fill(5));
      } else {
        const hlit = getBits(5) + 257;
        const hdist = getBits(5) + 1;
        const hclen = getBits(4) + 4;
        const order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
        const clLen = new Array(19).fill(0);
        for (let i = 0; i < hclen; i++) clLen[order[i]] = getBits(3);
        const clTree = buildTree(clLen);
        const lens: number[] = [];
        while (lens.length < hlit + hdist) {
          const sym = decodeSym(clTree);
          if (sym < 16) lens.push(sym);
          else if (sym === 16) {
            const n = getBits(2) + 3;
            const prev = lens[lens.length - 1];
            for (let i = 0; i < n; i++) lens.push(prev);
          } else if (sym === 17) {
            const n = getBits(3) + 3;
            for (let i = 0; i < n; i++) lens.push(0);
          } else {
            const n = getBits(7) + 11;
            for (let i = 0; i < n; i++) lens.push(0);
          }
        }
        litTree = buildTree(lens.slice(0, hlit));
        distTree = buildTree(lens.slice(hlit));
      }
      for (;;) {
        const sym = decodeSym(litTree);
        if (sym === 256) break;
        if (sym < 256) out.push(sym);
        else {
          const l = lenBase[sym - 257] + getBits(lenExtra[sym - 257]);
          const ds = decodeSym(distTree);
          const d = distBase[ds] + getBits(distExtra[ds]);
          const start = out.length - d;
          for (let i = 0; i < l; i++) out.push(out[start + i]);
        }
        if (out.length > 4 << 20) throw new Error("too large");
      }
    }
    if (last) break;
  }
  return new Uint8Array(out);
}
