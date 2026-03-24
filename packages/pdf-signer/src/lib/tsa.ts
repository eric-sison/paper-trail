/**
 * @file tsa.ts
 *
 * Handles RFC 3161 timestamping for PDF digital signatures.
 *
 * The TSA (Timestamp Authority) proves when the document was signed.
 * Without it, someone could theoretically backdate a signature.
 *
 *      Us                                 PNPKI TSA Server
 *      |                                        |
 *      |-- POST TimeStampReq -----------------> |
 *      |   (hash of our signature value)        |
 *      |                                        |
 *      |<-- TimeStampResp ----------------------|
 *      |   (signed token with time embedded)    |
 *
 * Why hash the signature value rather than the document?
 *   - The document's integrity is already proven by the signature itself
 *   - Sending the full PDF would be slow and a privacy concern
 *   - The TSA only needs to answer: "did this signature exist before time T?"
 *
 * This file is split into three layers:
 *
 *   Pure (no side effects, fully testable):
 *     - buildTSRequest()          — builds the DER-encoded TimeStampReq
 *     - extractTSToken()          — parses the DER-encoded TimeStampResp
 *     - injectTimestampIntoCMS()  — patches the token into CMS unsigned attrs
 *
 *   Side effects (HTTP, testable via injection):
 *     - requestTimestamp()        — sends the request and returns the token
 */

import forge from "node-forge";
import crypto from "crypto";
import { TSAError } from "../types.js";

// ─── Pure: Request Builder ────────────────────────────────────────────────────

/**
 * Builds a DER-encoded RFC 3161 TimeStampReq.
 *
 * Structure:
 *   TimeStampReq
 *     ├── version        INTEGER (always 1)
 *     ├── messageImprint
 *     │     ├── hashAlgorithm  SHA-256
 *     │     └── hashedMessage  the hash bytes
 *     ├── nonce          random 8 bytes (prevents replay attacks)
 *     └── certReq        TRUE — ask TSA to include its certificate
 *
 * @param hashBuffer - SHA-256 hash of the signature value bytes
 * @returns DER-encoded TimeStampReq as a Buffer
 */
export function buildTSRequest(hashBuffer: Buffer): Buffer {
  const sha256AlgId = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer("2.16.840.1.101.3.4.2.1").getBytes() // SHA-256
    ),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ""),
  ]);

  const messageImprint = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    sha256AlgId,
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, hashBuffer.toString("binary")),
  ]);

  const nonceBytes = crypto.randomBytes(8).toString("binary");

  const tsReq = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, "\x01"),
    messageImprint,
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, nonceBytes),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.BOOLEAN, false, "\xff"),
  ]);

  return Buffer.from(forge.asn1.toDer(tsReq).getBytes(), "binary");
}

// ─── Pure: Response Parser ────────────────────────────────────────────────────

/**
 * Parses a DER-encoded TimeStampResp and extracts the TimeStampToken.
 *
 * Structure:
 *   TimeStampResp
 *     ├── status PKIStatusInfo
 *     │     └── status INTEGER
 *     │           0 = granted
 *     │           1 = grantedWithMods
 *     │           2 = rejection
 *     │           3 = waiting
 *     │           4 = revocationWarning
 *     │           5 = revocationNotification
 *     └── timeStampToken ContentInfo ← returned as-is
 *
 * @param responseBuffer - Raw bytes from the TSA HTTP response
 * @returns DER-encoded TimeStampToken as a Buffer
 * @throws {TSAError} If the TSA rejected the request or token is missing
 */
export function extractTSToken(responseBuffer: Buffer): Buffer {
  const asn1 = forge.asn1.fromDer(responseBuffer.toString("binary"));
  const seq = asn1.value as forge.asn1.Asn1[];

  const pkiStatus = seq[0].value as forge.asn1.Asn1[];
  const statusCode = pkiStatus[0].value.toString().charCodeAt(0);

  if (statusCode !== 0 && statusCode !== 1) {
    const reasons: Record<number, string> = {
      2: "rejection",
      3: "waiting",
      4: "revocationWarning",
      5: "revocationNotification",
    };
    throw new TSAError(`TSA rejected the request: ${reasons[statusCode] ?? `status ${statusCode}`}`);
  }

  if (!seq[1]) throw new TSAError("TSA response did not include a TimeStampToken.");

  return Buffer.from(forge.asn1.toDer(seq[1]).getBytes(), "binary");
}

// ─── Pure: CMS Injection ──────────────────────────────────────────────────────

/**
 * Injects a TSA TimeStampToken into an existing CMS SignedData structure.
 *
 * The token is added as an unsigned attribute on the first SignerInfo:
 *   id-aa-signatureTimeStampToken (OID 1.2.840.113549.1.9.16.2.14)
 *
 * Why unsigned (not signed) attributes?
 *   Signed attributes are included in the hash — adding them after signing
 *   would invalidate the signature. Unsigned attributes are appended after
 *   signing and are not part of the hash — perfect for the timestamp token.
 *
 * CMS structure navigated:
 *   ContentInfo → SignedData → signerInfos → SignerInfo → unsignedAttrs
 *
 * @param cmsDer     - DER-encoded CMS SignedData
 * @param tsTokenDer - DER-encoded TimeStampToken from the TSA
 * @returns Modified CMS DER buffer with the timestamp token embedded
 */
export function injectTimestampIntoCMS(cmsDer: Buffer, tsTokenDer: Buffer): Buffer {
  const asn1 = forge.asn1.fromDer(cmsDer.toString("binary"));

  const contentInfo = asn1.value as forge.asn1.Asn1[];
  const signedData = (contentInfo[1].value as forge.asn1.Asn1[])[0];
  const signedDataSeq = signedData.value as forge.asn1.Asn1[];
  const signerInfosSet = signedDataSeq[signedDataSeq.length - 1];
  const signerInfo = (signerInfosSet.value as forge.asn1.Asn1[])[0];
  const signerInfoSeq = signerInfo.value as forge.asn1.Asn1[];

  // Build timestamp unsigned attribute
  // OID: id-aa-signatureTimeStampToken (1.2.840.113549.1.9.16.2.14)
  const tsAttr = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer("1.2.840.113549.1.9.16.2.14").getBytes()
    ),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
      forge.asn1.fromDer(tsTokenDer.toString("binary")),
    ]),
  ]);

  // Find existing unsignedAttrs [1] IMPLICIT SET or create new ones
  let unsignedAttrsIdx = -1;
  for (let i = 0; i < signerInfoSeq.length; i++) {
    if (signerInfoSeq[i].tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && signerInfoSeq[i].type === 1) {
      unsignedAttrsIdx = i;
      break;
    }
  }

  if (unsignedAttrsIdx >= 0) {
    (signerInfoSeq[unsignedAttrsIdx].value as forge.asn1.Asn1[]).push(tsAttr);
  } else {
    signerInfoSeq.push(forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 1, true, [tsAttr]));
  }

  return Buffer.from(forge.asn1.toDer(asn1).getBytes(), "binary");
}

// ─── Side Effect: HTTP ────────────────────────────────────────────────────────

/**
 * Requests an RFC 3161 timestamp from the TSA and returns the TimeStampToken.
 *
 * Steps:
 *   1. Hash the signature value bytes with SHA-256
 *   2. Build a TimeStampReq containing that hash
 *   3. POST it to the TSA URL
 *   4. Extract and return the TimeStampToken
 *
 * @param signatureValueBytes - Raw bytes of the CMS signature value
 * @param tsaUrl              - Timestamp Authority URL
 * @param timeoutMs           - Timeout in milliseconds (default 10 seconds)
 * @returns DER-encoded TimeStampToken as a Buffer
 * @throws {TSAError} If the request fails or times out
 */
export async function requestTimestamp(
  signatureValueBytes: Buffer,
  tsaUrl: string,
  timeoutMs = 10000
): Promise<Buffer> {
  const hash = crypto.createHash("sha256").update(signatureValueBytes).digest();
  const tsRequest = buildTSRequest(hash);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(tsaUrl, {
      method: "POST",
      headers: { "Content-Type": "application/timestamp-query" },
      body: new Uint8Array(tsRequest),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new TSAError(`HTTP error: ${response.status} ${response.statusText}`);
    }

    const responseBuffer = Buffer.from(await response.arrayBuffer());
    return extractTSToken(responseBuffer);
  } catch (err) {
    if ((err as Error).name === "AbortError") {
      throw new TSAError(`Request timed out after ${timeoutMs / 1000}s.`);
    }
    if (err instanceof TSAError) throw err;
    throw new TSAError((err as Error).message);
  } finally {
    clearTimeout(timer);
  }
}
