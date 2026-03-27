/**
 * @file tsa.ts
 *
 * RFC 3161 timestamp authority support.
 *
 * Pure functions (testable without network):
 *   buildTSRequest()         — DER-encoded TimeStampReq
 *   extractTSToken()         — parses TimeStampResp → token Buffer
 *   injectTimestampIntoCMS() — patches token into CMS unsignedAttrs
 *
 * Side effects (network):
 *   requestTimestamp()       — sends request, returns token with retry
 */

import forge from "node-forge";
import crypto from "crypto";
import type { RetryOptions } from "../types.js";
import { TSAError } from "../lib/errors.js";
import { withRetry, DEFAULT_TSA_RETRY } from "./retry.js";

// ─── Pure: Request Builder ────────────────────────────────────────────────────

/**
 * Builds a DER-encoded RFC 3161 TimeStampReq.
 * Uses SHA-256 for the message imprint hash.
 * Includes a random nonce to prevent replay attacks.
 */
export function buildTSRequest(hashBuffer: Buffer): Buffer {
  const sha256AlgId = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer("2.16.840.1.101.3.4.2.1").getBytes()
    ),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ""),
  ]);

  const messageImprint = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    sha256AlgId,
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OCTETSTRING,
      false,
      hashBuffer.toString("binary")
    ),
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
 * Parses a DER-encoded TimeStampResp and returns the TimeStampToken.
 *
 * @throws {TSAError} If the TSA rejected the request or token is absent
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
    throw new TSAError(reasons[statusCode] ?? `status code ${statusCode}`);
  }

  if (!seq[1]) throw new TSAError("Response did not include a TimeStampToken.");

  return Buffer.from(forge.asn1.toDer(seq[1]).getBytes(), "binary");
}

// ─── Pure: CMS Injection ──────────────────────────────────────────────────────

/**
 * Injects a TSA TimeStampToken into an existing CMS SignedData structure
 * as an unsigned attribute (id-aa-signatureTimeStampToken).
 *
 * Unsigned attributes are not covered by the signature hash, making them
 * safe to add after signing.
 */
export function injectTimestampIntoCMS(cmsDer: Buffer, tsTokenDer: Buffer): Buffer {
  const asn1 = forge.asn1.fromDer(cmsDer.toString("binary"));

  const contentInfo = asn1.value as forge.asn1.Asn1[];
  const signedData = (contentInfo[1].value as forge.asn1.Asn1[])[0];
  const signedDataSeq = signedData.value as forge.asn1.Asn1[];
  const signerInfosSet = signedDataSeq[signedDataSeq.length - 1];
  const signerInfo = (signerInfosSet.value as forge.asn1.Asn1[])[0];
  const signerInfoSeq = signerInfo.value as forge.asn1.Asn1[];

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

// ─── Side Effect: HTTP + retry ────────────────────────────────────────────────

/**
 * Requests an RFC 3161 timestamp token from the TSA with retry.
 *
 * @param signatureValueBytes - Raw CMS signature value (not the full PDF)
 * @param tsaUrl              - TSA endpoint
 * @param timeoutMs           - Per-attempt timeout in ms
 * @param retryOptions        - Retry configuration
 * @throws {TSAError} If all attempts fail
 */
export async function requestTimestamp(
  signatureValueBytes: Buffer,
  tsaUrl: string,
  timeoutMs = 10000,
  retryOptions: RetryOptions = DEFAULT_TSA_RETRY
): Promise<Buffer> {
  const hash = crypto.createHash("sha256").update(signatureValueBytes).digest();
  const tsRequest = buildTSRequest(hash);

  return withRetry(() => sendTSARequest(tsRequest, tsaUrl, timeoutMs), retryOptions);
}

async function sendTSARequest(tsRequest: Buffer, tsaUrl: string, timeoutMs: number): Promise<Buffer> {
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
