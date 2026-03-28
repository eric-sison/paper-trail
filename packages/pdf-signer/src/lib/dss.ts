/**
 * @file dss.ts
 *
 * Implements PAdES-B-LT by appending a DSS (Document Security Store)
 * dictionary to a signed PDF using a proper PDF incremental update.
 *
 * The DSS embeds validation data into the PDF so signatures can be
 * verified long-term without network access to OCSP/TSA servers.
 *
 * References:
 *   ETSI EN 319 102-1 §5.5
 *   ISO 32000-2 (PDF 2.0) §12.8.4.3
 */

import crypto from "crypto";
import forge from "node-forge";

/** Convert a forge certificate to DER-encoded Buffer */
export function certToDer(cert: forge.pki.Certificate): Buffer {
  return Buffer.from(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(), "binary");
}

/**
 * Appends a DSS dictionary to a signed PDF using a PDF incremental update.
 *
 * An incremental update appends new bytes to the PDF without modifying
 * existing bytes, preserving the cryptographic integrity of existing signatures.
 *
 * If anything goes wrong, returns the original signed PDF unchanged — DSS
 * is purely additive, so the signature remains valid without it.
 *
 * @param signedPdfBuffer  - The already-signed PDF
 * @param certsDer         - DER-encoded certificates from the signing chain
 * @param ocspsDer         - DER-encoded OCSP responses (may be empty)
 * @param signatureValue   - Raw signature value bytes (used as VRI key)
 * @param crlsDer          - DER-encoded CRL responses (used as fallback when OCSP is unavailable)
 */
export function appendDSSDictionary(
  signedPdfBuffer: Buffer,
  certsDer: Buffer[],
  ocspsDer: Buffer[],
  signatureValue: Buffer,
  crlsDer: Buffer[] = [] // ← accepted here
): Buffer {
  try {
    return buildIncrementalUpdate(signedPdfBuffer, certsDer, ocspsDer, signatureValue, crlsDer); // ← passed through
  } catch {
    // DSS is additive — return valid signed PDF without DSS
    return signedPdfBuffer;
  }
}

// ─── Incremental Update Builder ───────────────────────────────────────────────

function buildIncrementalUpdate(
  pdfBuffer: Buffer,
  certsDer: Buffer[],
  ocspsDer: Buffer[],
  signatureValue: Buffer,
  crlsDer: Buffer[] = [] // ← accepted here
): Buffer {
  const tail = parsePdfTail(pdfBuffer);
  if (!tail) throw new Error("Cannot parse PDF structure for DSS append");

  const { prevStartxref, nextObjNum: startObjNum, catalogNum } = tail;
  let nextObjNum = startObjNum;

  const parts: Buffer[] = [pdfBuffer];
  const xrefEntries: { num: number; offset: number }[] = [];
  let offset = pdfBuffer.length;

  // ── Helpers ──────────────────────────────────────────────────────────────

  function pushObj(num: number, body: string): void {
    xrefEntries.push({ num, offset });
    const buf = Buffer.from(`${num} 0 obj\n${body}\nendobj\n`, "latin1");
    parts.push(buf);
    offset += buf.length;
  }

  function pushStream(num: number, data: Buffer): void {
    xrefEntries.push({ num, offset });
    const header = Buffer.from(`${num} 0 obj\n<< /Length ${data.length} >>\nstream\n`, "latin1");
    const footer = Buffer.from("\nendstream\nendobj\n", "latin1");
    parts.push(header, data, footer);
    offset += header.length + data.length + footer.length;
  }

  // ── Cert streams ──────────────────────────────────────────────────────────
  const certNums: number[] = [];
  for (const certDer of certsDer) {
    const num = nextObjNum++;
    pushStream(num, certDer);
    certNums.push(num);
  }

  // ── OCSP streams ──────────────────────────────────────────────────────────
  const ocspNums: number[] = [];
  for (const ocspDer of ocspsDer) {
    const num = nextObjNum++;
    pushStream(num, ocspDer);
    ocspNums.push(num);
  }

  // ── CRL streams ───────────────────────────────────────────────────────────
  const crlNums: number[] = [];
  for (const crlDer of crlsDer) {
    const num = nextObjNum++;
    pushStream(num, crlDer);
    crlNums.push(num);
  }

  const certArr = certNums.length > 0 ? `[${certNums.map((n) => `${n} 0 R`).join(" ")}]` : "[]";
  const ocspArr = ocspNums.length > 0 ? `[${ocspNums.map((n) => `${n} 0 R`).join(" ")}]` : "[]";
  const crlArr = crlNums.length > 0 ? `[${crlNums.map((n) => `${n} 0 R`).join(" ")}]` : "[]";

  // ── VRI entry ─────────────────────────────────────────────────────────────
  // VRI key: uppercase hex SHA-1 of the signature value bytes
  const vriKey = crypto.createHash("sha1").update(signatureValue).digest("hex").toUpperCase();

  const vriEntryNum = nextObjNum++;
  pushObj(vriEntryNum, `<< /Cert ${certArr} /OCSP ${ocspArr} /CRL ${crlArr} >>`); // ← /CRL added

  // ── VRI dictionary ────────────────────────────────────────────────────────
  const vriDictNum = nextObjNum++;
  pushObj(vriDictNum, `<< /${vriKey} ${vriEntryNum} 0 R >>`);

  // ── DSS dictionary ────────────────────────────────────────────────────────
  const dssNum = nextObjNum++;
  pushObj(
    dssNum,
    `<< /Type /DSS /Certs ${certArr} /OCSPs ${ocspArr} /CRLs ${crlArr} /VRI ${vriDictNum} 0 R >>`
  ); // ← /CRLs added

  // ── Updated catalog (adds /DSS reference) ─────────────────────────────────
  const updatedCatalog = buildUpdatedCatalog(pdfBuffer, catalogNum, dssNum);
  pushObj(catalogNum, updatedCatalog);

  // ── Cross-reference table ─────────────────────────────────────────────────
  const xrefOffset = offset;
  const xrefLines: string[] = ["xref\n"];

  xrefEntries.sort((a, b) => a.num - b.num);

  // Write as individual subsections (one per object)
  for (const entry of xrefEntries) {
    xrefLines.push(`${entry.num} 1\n`);
    // Each xref entry MUST be exactly 20 bytes: 10+1+5+1+1+CR+LF = 20
    xrefLines.push(`${String(entry.offset).padStart(10, "0")} 00000 n\r\n`);
  }

  const xrefBuf = Buffer.from(xrefLines.join(""), "latin1");
  parts.push(xrefBuf);
  offset += xrefBuf.length;

  // ── Trailer ───────────────────────────────────────────────────────────────
  const trailer = Buffer.from(
    [
      "trailer\n",
      `<< /Size ${nextObjNum}`,
      ` /Root ${catalogNum} 0 R`,
      ` /Prev ${prevStartxref}`,
      " >>\n",
      `startxref\n${xrefOffset}\n%%EOF\n`,
    ].join(""),
    "latin1"
  );
  parts.push(trailer);

  return Buffer.concat(parts);
}

// ─── PDF Structure Helpers ────────────────────────────────────────────────────

interface PdfTailInfo {
  prevStartxref: number;
  nextObjNum: number;
  catalogNum: number;
}

function parsePdfTail(pdfBuffer: Buffer): PdfTailInfo | null {
  // Use latin1 to safely work with binary PDF bytes as a string
  const pdfStr = pdfBuffer.toString("latin1");

  // ── Find the last startxref offset ────────────────────────────────────
  const startxrefIdx = pdfStr.lastIndexOf("startxref");
  if (startxrefIdx === -1) return null;

  let pos = startxrefIdx + "startxref".length;
  while (pos < pdfStr.length && " \t\r\n".includes(pdfStr[pos])) pos++;

  let offsetStr = "";
  while (pos < pdfStr.length && /\d/.test(pdfStr[pos])) {
    offsetStr += pdfStr[pos++];
  }
  if (!offsetStr) return null;

  const prevStartxref = parseInt(offsetStr, 10);

  // ── Find /Size and /Root in the last trailer ───────────────────────────
  const trailerIdx = pdfStr.lastIndexOf("trailer");
  if (trailerIdx === -1) return null;

  const trailerSection = pdfStr.slice(trailerIdx, trailerIdx + 1024);

  const sizeMatch = trailerSection.match(/\/Size\s+(\d+)/);
  const rootMatch = trailerSection.match(/\/Root\s+(\d+)\s+\d+\s+R/);

  if (!sizeMatch || !rootMatch) return null;

  return {
    prevStartxref,
    nextObjNum: parseInt(sizeMatch[1], 10),
    catalogNum: parseInt(rootMatch[1], 10),
  };
}

function buildUpdatedCatalog(pdfBuffer: Buffer, catalogNum: number, dssNum: number): string {
  const pdfStr = pdfBuffer.toString("latin1");

  // Find the catalog object definition
  const objRegex = new RegExp(`${catalogNum}\\s+0\\s+obj`);
  const match = objRegex.exec(pdfStr);

  if (!match || match.index === undefined) {
    return `<< /Type /Catalog /DSS ${dssNum} 0 R >>`;
  }

  let pos = match.index + match[0].length;
  while (pos < pdfStr.length && " \t\r\n".includes(pdfStr[pos])) pos++;

  if (pdfStr[pos] !== "<" || pdfStr[pos + 1] !== "<") {
    return `<< /Type /Catalog /DSS ${dssNum} 0 R >>`;
  }

  // Extract the full dictionary using depth tracking
  let depth = 1;
  pos += 2;
  const dictStart = pos;

  while (pos < pdfStr.length && depth > 0) {
    if (pdfStr[pos] === "<" && pdfStr[pos + 1] === "<") {
      depth++;
      pos += 2;
    } else if (pdfStr[pos] === ">" && pdfStr[pos + 1] === ">") {
      depth--;
      pos += 2;
    } else {
      pos++;
    }
  }

  const dictContent = pdfStr.slice(dictStart, pos - 2);

  // Remove any existing /DSS entry and add the new one
  const cleaned = dictContent.replace(/\/DSS\s+\d+\s+\d+\s+R\s*/g, "");

  return `<<${cleaned}/DSS ${dssNum} 0 R >>`;
}
