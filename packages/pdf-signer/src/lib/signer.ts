/**
 * @file signer.ts
 *
 * Orchestrates the full PNPKI PDF signing pipeline:
 *
 *   1. Parse the .p12 file          — extract private key, cert chain, cert info
 *   2. Guard checks                 — reject expired certs, warn if expiring soon
 *   3. OCSP check                   — verify cert is not revoked (non-blocking)
 *   4. Draw signature appearance    — add visible stamp to the PDF page
 *   5. Add ByteRange placeholder    — reserve space for the CMS signature bytes
 *   6. Sign with @signpdf           — build CMS SignedData, RSA-SHA256 sign
 *   7. Extract CMS from signed PDF  — locate /Contents, trim zero padding
 *   8. Request TSA timestamp        — RFC 3161 token proving time of signing
 *   9. Inject timestamp into CMS    — add token as unsigned attribute
 *  10. Write patched CMS back       — return the final signed PDF buffer
 *
 * OCSP and TSA are injectable via SignOptions:
 *   options.ocspChecker  — defaults to checkOCSP, pass a mock in tests
 *   options.tsaRequester — defaults to requestTimestamp, pass a mock in tests
 *
 * Signing is non-destructive — the original PDF buffer is never modified.
 */

import { PDFDocument, rgb, StandardFonts } from "pdf-lib";
import { pdflibAddPlaceholder } from "@signpdf/placeholder-pdf-lib";
import { P12Signer } from "@signpdf/signer-p12";
import { createRequire } from "module";
import forge from "node-forge";

import { parseP12 } from "./cert-utils.js";
import { checkOCSP } from "./ocsp.js";
import { requestTimestamp, injectTimestampIntoCMS } from "./tsa.js";

import type { SignOptions, SignResult, CertInfo, OCSPResult } from "../types.js";
import { CertExpiredError, CertRevokedError, InvalidPasswordError, InvalidPdfError } from "../types.js";

export type { SignOptions, SignResult, CertInfo, OCSPResult };

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * Reserved byte length for the CMS signature placeholder in the PDF.
 * Must accommodate: cert chain (~4KB) + CMS (~1KB) + TSA token (~3KB) + overhead.
 * Increase if you see "exceeds placeholder size" errors.
 */
const SIGNATURE_LENGTH = 32768;

const FALLBACK_OCSP_URL = "http://ocsp.npki.gov.ph";
const FALLBACK_TSA_URL = "http://tsa.npki.gov.ph";

// ─── Step 4: Signature Appearance ────────────────────────────────────────────

/**
 * Draws a visible signature stamp on the target PDF page.
 *
 * If options.signatureImage is provided, the stamp shows only the image
 * (aspect-ratio preserved, no stretching). Otherwise it shows the standard
 * PNPKI text stamp (name, org, date, reason, location, serial number).
 *
 * Mutates the PDFDocument in place.
 */
async function drawSignatureAppearance(pdfDoc: PDFDocument, certInfo: CertInfo, options: SignOptions): Promise<void> {
  const pages = pdfDoc.getPages();
  const pos = options.signaturePosition;

  const pageIdx = pos ? Math.min(pos.page - 1, pages.length - 1) : pages.length - 1;

  const page = pages[pageIdx];
  const { width } = page.getSize();

  const BOX_W = pos?.width ?? 230;
  const BOX_H = pos?.height ?? 78;
  const boxX = pos?.x ?? width - BOX_W - 15;
  const boxY = pos?.y ?? 15;

  const NAVY = rgb(0.086, 0.22, 0.467);
  const LIGHT_BLUE = rgb(0.93, 0.96, 1.0);
  const DARK_TEXT = rgb(0.1, 0.1, 0.1);
  const MID_TEXT = rgb(0.3, 0.3, 0.3);

  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontOblique = await pdfDoc.embedFont(StandardFonts.HelveticaOblique);

  // Text stamp — shown when no image is provided
  const drawTextStamp = () => {
    page.drawRectangle({
      x: boxX,
      y: boxY,
      width: BOX_W,
      height: BOX_H,
      color: LIGHT_BLUE,
      borderColor: NAVY,
      borderWidth: 1.5,
    });

    page.drawRectangle({
      x: boxX,
      y: boxY,
      width: 6,
      height: BOX_H,
      color: NAVY,
    });

    const textX = boxX + 12;

    page.drawText("DIGITALLY SIGNED BY PNPKI", {
      x: textX,
      y: boxY + BOX_H - 13,
      size: 5.5,
      font: fontBold,
      color: NAVY,
    });

    page.drawLine({
      start: { x: textX, y: boxY + BOX_H - 16 },
      end: { x: boxX + BOX_W - 8, y: boxY + BOX_H - 16 },
      thickness: 0.5,
      color: NAVY,
    });

    const nameText = certInfo.commonName.length > 32 ? certInfo.commonName.slice(0, 29) + "..." : certInfo.commonName;
    page.drawText(nameText, {
      x: textX,
      y: boxY + BOX_H - 27,
      size: 7.5,
      font: fontBold,
      color: DARK_TEXT,
    });

    if (certInfo.organization) {
      const orgText =
        certInfo.organization.length > 38 ? certInfo.organization.slice(0, 35) + "..." : certInfo.organization;
      page.drawText(orgText, {
        x: textX,
        y: boxY + BOX_H - 37,
        size: 6,
        font: fontRegular,
        color: MID_TEXT,
      });
    }

    const signDate = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
    page.drawText(`Date: ${signDate}`, {
      x: textX,
      y: boxY + BOX_H - 49,
      size: 5.5,
      font: fontRegular,
      color: MID_TEXT,
    });

    const reasonText = (options.reason || "I have reviewed this document").slice(0, 40);
    page.drawText(`Reason: ${reasonText}`, {
      x: textX,
      y: boxY + BOX_H - 59,
      size: 5.5,
      font: fontRegular,
      color: MID_TEXT,
    });

    const locationText = (options.location || "Philippines").slice(0, 40);
    page.drawText(`Location: ${locationText}`, {
      x: textX,
      y: boxY + BOX_H - 69,
      size: 5.5,
      font: fontRegular,
      color: MID_TEXT,
    });

    page.drawText(`SN: ${certInfo.serialNumber.slice(0, 16)}`, {
      x: boxX + BOX_W - 70,
      y: boxY + 4,
      size: 4.5,
      font: fontOblique,
      color: rgb(0.55, 0.55, 0.55),
    });
  };

  if (options.signatureImage) {
    try {
      const image = await pdfDoc.embedPng(options.signatureImage).catch(() => pdfDoc.embedJpg(options.signatureImage!));

      const imgDims = image.size();
      const imgRatio = imgDims.width / imgDims.height;
      const drawW = BOX_W;
      const drawH = BOX_W / imgRatio;

      page.drawImage(image, {
        x: boxX,
        y: boxY,
        width: drawW,
        height: drawH,
      });
    } catch {
      drawTextStamp();
    }
  } else {
    drawTextStamp();
  }
}

// ─── DER Utilities ────────────────────────────────────────────────────────────

/**
 * Trims trailing null bytes from a zero-padded DER buffer.
 *
 * PDF signature placeholders are padded with 0x00 to fill reserved space.
 * forge.asn1.fromDer throws "Unparsed DER bytes remain" if given a padded
 * buffer, so we read the DER length header to find the real end.
 */
export function trimDerBuffer(buf: Buffer): Buffer {
  if (buf.length < 4 || buf[0] !== 0x30) return buf;

  let realLength: number;
  if (buf[1] < 0x80) {
    realLength = 2 + buf[1];
  } else {
    const numLenBytes = buf[1] & 0x7f;
    let len = 0;
    for (let i = 0; i < numLenBytes; i++) {
      len = (len << 8) | buf[2 + i];
    }
    realLength = 2 + numLenBytes + len;
  }

  return buf.slice(0, realLength);
}

/**
 * Extracts the raw signature value bytes from a CMS SignedData DER buffer.
 * These bytes are hashed and sent to the TSA.
 *
 * Navigates: ContentInfo → SignedData → signerInfos → SignerInfo → signature
 */
export function extractSignatureValueFromCMS(cmsDer: Buffer): Buffer {
  const asn1 = forge.asn1.fromDer(cmsDer.toString("binary"));
  const contentInfo = asn1.value as forge.asn1.Asn1[];
  const signedData = (contentInfo[1].value as forge.asn1.Asn1[])[0];
  const signedDataSeq = signedData.value as forge.asn1.Asn1[];
  const signerInfosSet = signedDataSeq[signedDataSeq.length - 1];
  const signerInfo = (signerInfosSet.value as forge.asn1.Asn1[])[0];
  const signerInfoSeq = signerInfo.value as forge.asn1.Asn1[];

  for (let i = signerInfoSeq.length - 1; i >= 0; i--) {
    if (signerInfoSeq[i].type === forge.asn1.Type.OCTETSTRING) {
      return Buffer.from(signerInfoSeq[i].value as string, "binary");
    }
  }

  throw new Error("Could not find signature value in CMS SignerInfo.");
}

// ─── Step 7-10: TSA Injection ─────────────────────────────────────────────────

/**
 * Post-processes a signed PDF to inject a TSA timestamp token.
 *
 * @signpdf has no TSA support, so we:
 *   1. Locate /ByteRange and /Contents in the signed PDF
 *   2. Decode /Contents hex → trim zero padding → parse CMS
 *   3. Extract signature value → request TSA token
 *   4. Inject token as unsigned attribute
 *   5. Write patched CMS back into the PDF
 */
async function injectTSAIntoSignedPdf(
  signedPdf: Buffer,
  tsaUrl: string,
  tsaRequester: (bytes: Buffer, url: string, timeout?: number) => Promise<Buffer>,
  timeoutMs: number
): Promise<Buffer> {
  const pdfStr = signedPdf.toString("binary");

  const byteRangeMatch = pdfStr.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
  if (!byteRangeMatch) throw new Error("Could not find /ByteRange in signed PDF.");

  const b0 = parseInt(byteRangeMatch[1], 10);
  const b1 = parseInt(byteRangeMatch[2], 10);
  const b2 = parseInt(byteRangeMatch[3], 10);

  const contentsStart = b0 + b1 + 1;
  const contentsEnd = b2 - 1;
  const contentsHex = pdfStr.slice(contentsStart, contentsEnd);

  const cmsDer = trimDerBuffer(Buffer.from(contentsHex, "hex"));
  const signatureValueBytes = extractSignatureValueFromCMS(cmsDer);
  const tsTokenDer = await tsaRequester(signatureValueBytes, tsaUrl, timeoutMs);
  const patchedCmsDer = injectTimestampIntoCMS(cmsDer, tsTokenDer);

  if (patchedCmsDer.length * 2 > contentsHex.length) {
    throw new Error(
      `TSA-patched CMS (${patchedCmsDer.length * 2} hex chars) exceeds ` +
        `placeholder size (${contentsHex.length} hex chars). ` +
        `Increase SIGNATURE_LENGTH in signer.ts.`
    );
  }

  const patchedHex = patchedCmsDer.toString("hex").padEnd(contentsHex.length, "0");
  const result = Buffer.from(signedPdf);
  result.write(patchedHex, contentsStart, "ascii");

  return result;
}

// ─── Main Entry Point ─────────────────────────────────────────────────────────

/**
 * Signs a PDF document using a PNPKI certificate.
 *
 * OCSP and TSA are injectable via options:
 *   options.ocspChecker  — pass a mock to skip real OCSP in tests
 *   options.tsaRequester — pass a mock to skip real TSA in tests
 *   options.skipOCSP     — skip OCSP entirely
 *   options.skipTSA      — skip TSA entirely
 *
 * @throws {InvalidPasswordError} If the P12 password is wrong
 * @throws {InvalidP12Error}      If the P12 file is invalid
 * @throws {InvalidPdfError}      If the PDF file is invalid
 * @throws {CertExpiredError}     If the certificate has expired
 * @throws {CertRevokedError}     If the certificate has been revoked
 */
export async function signPDF(options: SignOptions): Promise<SignResult> {
  const warnings: string[] = [];

  // ── Step 1: Parse .p12 ──────────────────────────────────────────────────
  const { certInfo, certChain } = parseP12(options.p12Buffer, options.password);

  // ── Step 2: Guard checks ─────────────────────────────────────────────────
  if (certInfo.isExpired) {
    throw new CertExpiredError(certInfo.validTo.toLocaleDateString());
  }

  if (certInfo.daysUntilExpiry <= 30) {
    warnings.push(
      `Certificate expires in ${certInfo.daysUntilExpiry} day(s) ` + `on ${certInfo.validTo.toLocaleDateString()}.`
    );
  }

  // ── Step 3: OCSP check ───────────────────────────────────────────────────
  const ocspChecker = options.ocspChecker ?? checkOCSP;
  const ocspTimeoutMs = options.ocspTimeoutMs ?? 8000;

  let ocspResult: OCSPResult = {
    status: "unknown",
    message: "OCSP check skipped — only one certificate in chain.",
  };

  if (!options.skipOCSP && certChain.length >= 2) {
    ocspResult = await ocspChecker(certChain[0], certChain[1], certInfo.ocspUrl ?? FALLBACK_OCSP_URL, ocspTimeoutMs);

    if (ocspResult.status === "revoked") throw new CertRevokedError();
    if (ocspResult.status === "unreachable") warnings.push(ocspResult.message);
  }

  // ── Step 4: Draw visible signature appearance ────────────────────────────
  let pdfDoc: PDFDocument;
  try {
    pdfDoc = await PDFDocument.load(options.pdfBuffer);
  } catch {
    throw new InvalidPdfError();
  }

  await drawSignatureAppearance(pdfDoc, certInfo, options);
  const pdfWithAppearance = Buffer.from(await pdfDoc.save({ useObjectStreams: false }));

  // ── Step 5: Add ByteRange placeholder ───────────────────────────────────
  const pdfDoc2 = await PDFDocument.load(pdfWithAppearance);
  pdflibAddPlaceholder({
    pdfDoc: pdfDoc2,
    reason: options.reason || "I have reviewed this document",
    contactInfo: certInfo.email || "pnpki@dict.gov.ph",
    name: certInfo.commonName,
    location: options.location || "Philippines",
    signatureLength: SIGNATURE_LENGTH,
  });
  const pdfWithPlaceholder = Buffer.from(await pdfDoc2.save({ useObjectStreams: false }));

  // ── Step 6: Sign with @signpdf ───────────────────────────────────────────
  const require = createRequire(import.meta.url);
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const signpdf = (require("@signpdf/signpdf") as { default: { sign: Function } }).default;
  const p12Signer = new P12Signer(options.p12Buffer, { passphrase: options.password });

  let signedPdf: Buffer;
  try {
    signedPdf = await signpdf.sign(pdfWithPlaceholder, p12Signer);
  } catch (err) {
    const msg = (err as Error).message ?? "";
    if (msg.includes("passphrase") || msg.includes("password") || msg.includes("decrypt")) {
      throw new InvalidPasswordError();
    }
    throw err;
  }

  // ── Steps 7-10: TSA injection ────────────────────────────────────────────
  const tsaRequester = options.tsaRequester ?? requestTimestamp;
  const tsaTimeoutMs = options.tsaTimeoutMs ?? 10000;
  const tsaUrl = certInfo.tsaUrl ?? FALLBACK_TSA_URL;

  let timestamped = false;

  if (!options.skipTSA) {
    try {
      signedPdf = await injectTSAIntoSignedPdf(signedPdf, tsaUrl, tsaRequester, tsaTimeoutMs);
      timestamped = true;
    } catch (err) {
      warnings.push(
        `TSA timestamp could not be applied: ${(err as Error).message}. ` +
          `The signature is valid but may not support long-term verification.`
      );
    }
  }

  return { signedPdf, certInfo, ocspResult, timestamped, warnings };
}
