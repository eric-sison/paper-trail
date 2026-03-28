/**
 * @file signer.ts
 *
 * Orchestrates the full PAdES PDF signing pipeline:
 *
 *   1.  Parse + validate .p12    — private key, cert chain, cert info
 *   2.  Input validation         — size limits, expired cert checks
 *   3.  OCSP check               — revocation check with CRL fallback + retry
 *   4.  Draw signature stamp     — visible appearance on PDF page
 *   5.  ByteRange placeholder    — reserve CMS space with ETSI.CAdES subfilter
 *   6.  Sign                     — RSA-SHA256 CMS SignedData
 *   7.  TSA timestamp            — RFC 3161 token injection with retry
 *   8.  DSS dictionary           — PAdES-B-LT via incremental PDF update
 *
 * Phase changes from v1:
 *   1a. ETSI.CAdES.detached subfilter (true PAdES compliance)
 *   1b. DSS dictionary (PAdES-B-LT)
 *   2a. Proper ByteRange parser (no regex)
 *   2c. Chain validation in parseP12
 *   3a. Password wiping (best effort)
 *   3b. Input size limits inside the library
 *   4a. CRL fallback in checkOCSP
 *   4b. Retry logic in OCSP + TSA
 */

import { PDFDocument, rgb, StandardFonts } from "pdf-lib";
import { pdflibAddPlaceholder } from "@signpdf/placeholder-pdf-lib";
import { P12Signer } from "@signpdf/signer-p12";
import { SUBFILTER_ETSI_CADES_DETACHED } from "@signpdf/utils";
import { createRequire } from "module";
import forge from "node-forge";

import { parseP12 } from "./cert-utils.js";
import { checkOCSP } from "./ocsp.js";
import { requestTimestamp, injectTimestampIntoCMS } from "./tsa.js";
import { findByteRange, extractContentsHex } from "./pdf-parser.js";
import { appendDSSDictionary, certToDer } from "./dss.js";
import { DEFAULT_OCSP_RETRY, DEFAULT_TSA_RETRY } from "./retry.js";

import type { SignOptions, SignResult, CertInfo, OCSPResult } from "../types.js";
import { CertExpiredError, CertRevokedError, InvalidPdfError, InvalidPasswordError } from "./errors.js";

export type { SignOptions, SignResult, CertInfo, OCSPResult };

// ─── Defaults ─────────────────────────────────────────────────────────────────

const SIGNATURE_LENGTH = 32768; // 32KB — accommodates chain + TSA token
const FALLBACK_OCSP_URL = "http://ocsp.npki.gov.ph";
const FALLBACK_TSA_URL = "http://tsa.npki.gov.ph";
const DEFAULT_MAX_PDF_SIZE = 100 * 1024 * 1024; // 100MB
const DEFAULT_MAX_P12_SIZE = 5 * 1024 * 1024; // 5MB

// ─── Step 4: Signature Appearance ────────────────────────────────────────────

async function drawSignatureAppearance(
  pdfDoc: PDFDocument,
  certInfo: CertInfo,
  options: SignOptions
): Promise<void> {
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

  const stampHeader = options.stampHeader ?? "DIGITALLY SIGNED BY PNPKI";

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

    const tx = boxX + 12;

    page.drawText(stampHeader, {
      x: tx,
      y: boxY + BOX_H - 13,
      size: 5.5,
      font: fontBold,
      color: NAVY,
    });

    page.drawLine({
      start: { x: tx, y: boxY + BOX_H - 16 },
      end: { x: boxX + BOX_W - 8, y: boxY + BOX_H - 16 },
      thickness: 0.5,
      color: NAVY,
    });

    const nameText =
      certInfo.commonName.length > 32 ? certInfo.commonName.slice(0, 29) + "..." : certInfo.commonName;

    page.drawText(nameText, {
      x: tx,
      y: boxY + BOX_H - 27,
      size: 7.5,
      font: fontBold,
      color: DARK_TEXT,
    });

    if (certInfo.organization) {
      const orgText =
        certInfo.organization.length > 38
          ? certInfo.organization.slice(0, 35) + "..."
          : certInfo.organization;

      page.drawText(orgText, {
        x: tx,
        y: boxY + BOX_H - 37,
        size: 6,
        font: fontRegular,
        color: MID_TEXT,
      });
    }

    const signDate = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
    page.drawText(`Date: ${signDate}`, {
      x: tx,
      y: boxY + BOX_H - 49,
      size: 5.5,
      font: fontRegular,
      color: MID_TEXT,
    });

    const reasonText = (options.reason || "I have reviewed this document").slice(0, 40);
    page.drawText(`Reason: ${reasonText}`, {
      x: tx,
      y: boxY + BOX_H - 59,
      size: 5.5,
      font: fontRegular,
      color: MID_TEXT,
    });

    const locationText = (options.location || "Philippines").slice(0, 40);
    page.drawText(`Location: ${locationText}`, {
      x: tx,
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
      const image = await pdfDoc
        .embedPng(options.signatureImage)
        .catch(() => pdfDoc.embedJpg(options.signatureImage!));

      const imgDims = image.size();
      const imgRatio = imgDims.width / imgDims.height;
      const boxRatio = BOX_W / BOX_H;

      // Contain fit — respect both BOX_W and BOX_H
      let drawW: number;
      let drawH: number;

      if (imgRatio > boxRatio) {
        // Image wider than box — constrain by width
        drawW = BOX_W;
        drawH = BOX_W / imgRatio;
      } else {
        // Image taller than box — constrain by height
        drawH = BOX_H;
        drawW = BOX_H * imgRatio;
      }

      // Center within the box
      const offsetX = (BOX_W - drawW) / 2;
      const offsetY = (BOX_H - drawH) / 2;

      page.drawImage(image, {
        x: boxX + offsetX,
        y: boxY + offsetY,
        width: drawW,
        height: drawH,
      });
    } catch {
      drawTextStamp();
    }
  }
}

// ─── DER Utilities ────────────────────────────────────────────────────────────

/**
 * Trims trailing null bytes from a zero-padded DER buffer.
 * PDF /Contents placeholders are padded with 0x00 — forge rejects them without trimming.
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

  return buf.subarray(0, realLength);
}

/**
 * Extracts the raw signature value bytes from a CMS SignedData DER buffer.
 * These bytes are hashed and sent to the TSA.
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

// ─── Steps 7–10: TSA Injection ────────────────────────────────────────────────

async function injectTSAIntoSignedPdf(
  signedPdf: Buffer,
  tsaUrl: string,
  tsaRequester: SignOptions["tsaRequester"],
  timeoutMs: number,
  retryOptions: SignOptions["tsaRetryOptions"]
): Promise<{ pdfBuffer: Buffer; signatureValueBytes: Buffer }> {
  const byteRange = findByteRange(signedPdf);
  if (!byteRange) throw new Error("Could not locate /ByteRange in signed PDF.");

  const contentsHex = extractContentsHex(signedPdf, byteRange);
  const cmsDer = trimDerBuffer(Buffer.from(contentsHex, "hex"));
  const signatureValueBytes = extractSignatureValueFromCMS(cmsDer);

  const actualTsaRequester = tsaRequester ?? requestTimestamp;

  const maxRetries = retryOptions?.retries ?? 0;
  const delayMs = retryOptions?.initialDelayMs ?? 1000;
  const backoffFactor = retryOptions?.backoffFactor ?? 1;

  let lastError: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const tsTokenDer = await actualTsaRequester(signatureValueBytes, tsaUrl, timeoutMs);

      const patchedCmsDer = injectTimestampIntoCMS(cmsDer, tsTokenDer);

      if (patchedCmsDer.length * 2 > contentsHex.length) {
        throw new Error(
          `Patched CMS (${patchedCmsDer.length * 2} hex) exceeds placeholder ` +
            `(${contentsHex.length} hex). Increase SIGNATURE_LENGTH.`
        );
      }

      const [b0, b1] = byteRange;
      const contentsStart = b0 + b1 + 1;
      const patchedHex = patchedCmsDer.toString("hex").padEnd(contentsHex.length, "0");
      const result = Buffer.from(signedPdf);
      result.write(patchedHex, contentsStart, "ascii");

      return { pdfBuffer: result, signatureValueBytes };
    } catch (err) {
      lastError = err;
      if (attempt < maxRetries) {
        const shouldRetry = retryOptions?.shouldRetry;
        if (shouldRetry && !shouldRetry(err as Error)) break;
        const wait = delayMs * Math.pow(backoffFactor, attempt);
        await new Promise((res) => setTimeout(res, wait));
      }
    }
  }

  throw lastError;
}

// ─── Main Entry Point ─────────────────────────────────────────────────────────

/**
 * Signs a PDF document producing a PAdES-B-LT compliant signature.
 *
 * Produces:
 *   - ETSI.CAdES.detached subfilter (true PAdES)
 *   - RFC 3161 timestamp
 *   - DSS dictionary with embedded OCSP + certificate chain
 *
 * @throws {InvalidPdfError}      PDF buffer is invalid or too large
 * @throws {InvalidP12Error}      P12 buffer is invalid
 * @throws {InvalidPasswordError} Wrong P12 password
 * @throws {CertExpiredError}     Certificate has expired
 * @throws {CertRevokedError}     Certificate has been revoked
 */
export async function signPDF(options: SignOptions): Promise<SignResult> {
  const warnings: string[] = [];

  // ── Phase 3b: Input size validation ────────────────────────────────────
  const maxPdf = options.maxPdfSize ?? DEFAULT_MAX_PDF_SIZE;
  const maxP12 = options.maxP12Size ?? DEFAULT_MAX_P12_SIZE;

  if (options.pdfBuffer.length > maxPdf) {
    throw new InvalidPdfError(
      `PDF size (${(options.pdfBuffer.length / 1024 / 1024).toFixed(1)}MB) ` +
        `exceeds limit (${maxPdf / 1024 / 1024}MB).`
    );
  }

  if (options.p12Buffer.length > maxP12) {
    throw new Error(
      `P12 size (${(options.p12Buffer.length / 1024).toFixed(1)}KB) ` + `exceeds limit (${maxP12 / 1024}KB).`
    );
  }

  // ── Step 1: Parse .p12 (Phase 3a: password wiped in parseP12) ──────────
  const { certInfo, certChain } = parseP12(options.p12Buffer, options.password);

  // ── Step 2: Guard checks ────────────────────────────────────────────────
  if (certInfo.isExpired) {
    const expiredMsg = `Certificate expired on ${certInfo.validTo.toLocaleDateString()}.`;

    if (options.rejectIfExpired !== false) {
      throw new CertExpiredError(certInfo.validTo.toLocaleDateString());
    }

    console.warn(`[pdf-signer] WARNING: ${expiredMsg} Proceeding anyway (rejectIfExpired=false).`);
    warnings.push(expiredMsg);
  }

  if (certInfo.daysUntilExpiry <= 30) {
    warnings.push(
      `Certificate expires in ${certInfo.daysUntilExpiry} day(s) ` +
        `on ${certInfo.validTo.toLocaleDateString()}.`
    );
  }

  // ── Step 3: OCSP check with CRL fallback + retry ────────────────────────
  const ocspChecker = options.ocspChecker ?? checkOCSP;
  const ocspTimeoutMs = options.ocspTimeoutMs ?? 8000;
  const ocspRetry = options.ocspRetryOptions ?? DEFAULT_OCSP_RETRY;
  const enableCRL = options.enableCRLFallback ?? true;
  const fallbackOcspUrl = options.fallbackOcspUrl ?? FALLBACK_OCSP_URL;

  let ocspResult: OCSPResult = {
    status: "unknown",
    message: "OCSP check skipped — only one certificate in chain.",
  };

  if (!options.skipOCSP && certChain.length >= 2) {
    ocspResult = await ocspChecker(
      certChain[0],
      certChain[1],
      certInfo.ocspUrl ?? fallbackOcspUrl,
      ocspTimeoutMs,
      ocspRetry,
      enableCRL
    );

    if (ocspResult.status === "revoked") throw new CertRevokedError();
    if (ocspResult.status === "unreachable") warnings.push(ocspResult.message);
  }

  // ── Step 4: Draw visible signature appearance ───────────────────────────
  let pdfDoc: PDFDocument;
  try {
    pdfDoc = await PDFDocument.load(options.pdfBuffer);
  } catch {
    throw new InvalidPdfError();
  }

  await drawSignatureAppearance(pdfDoc, certInfo, options);
  const pdfWithAppearance = Buffer.from(await pdfDoc.save({ useObjectStreams: false }));

  // ── Step 5: ByteRange placeholder (Phase 1a: ETSI.CAdES.detached) ──────
  const pdfDoc2 = await PDFDocument.load(pdfWithAppearance);
  pdflibAddPlaceholder({
    pdfDoc: pdfDoc2,
    reason: options.reason || "I have reviewed this document",
    contactInfo: options.contactInfo ?? certInfo.email ?? "pnpki@dict.gov.ph",
    name: certInfo.commonName,
    location: options.location || "Philippines",
    signatureLength: SIGNATURE_LENGTH,
    subFilter: SUBFILTER_ETSI_CADES_DETACHED,
  });
  const pdfWithPlaceholder = Buffer.from(await pdfDoc2.save({ useObjectStreams: false }));

  // ── Step 6: Sign ────────────────────────────────────────────────────────
  const require = createRequire(import.meta.url);
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const signpdf = (require("@signpdf/signpdf") as { default: { sign: Function } }).default;

  const passwordStr = (
    options.password instanceof Buffer ? options.password.toString("utf8") : options.password
  ) as string;

  const p12Signer = new P12Signer(options.p12Buffer, {
    passphrase: passwordStr,
  });

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

  // ── Steps 7–8: TSA timestamp ────────────────────────────────────────────
  const tsaUrl = certInfo.tsaUrl ?? options.fallbackTsaUrl ?? FALLBACK_TSA_URL;
  const tsaTimeoutMs = options.tsaTimeoutMs ?? 10000;
  const tsaRetry = options.tsaRetryOptions ?? DEFAULT_TSA_RETRY;

  let timestamped = false;
  let signatureValueBytes: Buffer | null = null;

  if (!options.skipTSA) {
    try {
      const result = await injectTSAIntoSignedPdf(
        signedPdf,
        tsaUrl,
        options.tsaRequester,
        tsaTimeoutMs,
        tsaRetry
      );
      signedPdf = result.pdfBuffer;
      signatureValueBytes = result.signatureValueBytes;
      timestamped = true;
    } catch (err) {
      warnings.push(
        `TSA timestamp could not be applied: ${(err as Error).message}. ` +
          `Signature is valid but may not support long-term verification.`
      );
    }
  }

  // ── Phase 1b: DSS dictionary (PAdES-B-LT) ──────────────────────────────
  let dssAdded = false;

  if (!options.skipDSS && signatureValueBytes) {
    try {
      const certsDer = certChain.map(certToDer);
      const ocspsDer = ocspResult.responseBytes ? [ocspResult.responseBytes] : [];

      signedPdf = appendDSSDictionary(signedPdf, certsDer, ocspsDer, signatureValueBytes);
      dssAdded = true;
    } catch (err) {
      warnings.push(
        `DSS dictionary could not be added: ${(err as Error).message}. ` +
          `Signature is valid but long-term validation data is not embedded.`
      );
    }
  }

  return {
    signedPdf,
    certInfo,
    ocspResult,
    timestamped,
    dssAdded,
    warnings,
  };
}
