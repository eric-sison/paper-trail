/**
 * @file ocsp.ts
 *
 * RFC 6960 OCSP certificate revocation checking.
 *
 * Pure functions (testable without network):
 *   buildOCSPRequest()   — DER-encoded OCSP request
 *   parseOCSPResponse()  — parses DER response → OCSPStatus
 *
 * Side effects (network):
 *   checkOCSP()          — sends request, returns OCSPResult
 *                          includes CRL fallback + retry
 */

import forge from "node-forge";
import type { OCSPResult, OCSPStatus, RetryOptions } from "../types.js";
import { checkCRL, extractCRLUrl } from "./crl.js";
import { withRetry, DEFAULT_OCSP_RETRY } from "./retry.js";

// ─── Pure: Request Builder ────────────────────────────────────────────────────

/**
 * Builds a DER-encoded OCSP request for a single certificate (RFC 6960).
 *
 * CertID uses SHA-1 hashes of the issuer's DN and public key, plus the
 * cert serial number. We hash the ISSUER's data (not the cert's own) because
 * the OCSP server indexes certs by who issued them.
 */
export function buildOCSPRequest(cert: forge.pki.Certificate, issuerCert: forge.pki.Certificate): Buffer {
  const issuerDNDer = forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(issuerCert.subject)).getBytes();
  const issuerNameHash = forge.md.sha1.create().update(issuerDNDer).digest().getBytes();

  const issuerKeyAsn1 = forge.pki.publicKeyToAsn1(issuerCert.publicKey as forge.pki.PublicKey);
  const spkiValue = (issuerKeyAsn1 as forge.asn1.Asn1).value as forge.asn1.Asn1[];
  const keyBytes = forge.asn1.toDer(spkiValue[1]).getBytes().slice(1);
  const issuerKeyHash = forge.md.sha1.create().update(keyBytes).digest().getBytes();

  const serialHex = cert.serialNumber;
  const serialBytes = Buffer.from(serialHex.length % 2 === 0 ? serialHex : "0" + serialHex, "hex").toString("binary");

  const sha1AlgId = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer("1.3.14.3.2.26").getBytes()
    ),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ""),
  ]);

  const certId = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    sha1AlgId,
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, issuerNameHash),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, issuerKeyHash),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, serialBytes),
  ]);

  const request = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [certId]);
  const tbsRequest = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [request]),
  ]);
  const ocspRequest = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [tbsRequest]);

  return Buffer.from(forge.asn1.toDer(ocspRequest).getBytes(), "binary");
}

// ─── Pure: Response Parser ────────────────────────────────────────────────────

/**
 * Parses a DER-encoded OCSP response and extracts the certificate status.
 * Returns 'unknown' on any parse error.
 */
export function parseOCSPResponse(responseBuffer: Buffer): OCSPStatus {
  try {
    const asn1 = forge.asn1.fromDer(responseBuffer.toString("binary"));
    const seq = asn1.value as forge.asn1.Asn1[];

    const responseStatus = seq[0].value.toString().charCodeAt(0);
    if (responseStatus !== 0) return "unknown";

    const responseBytes = seq[1];
    if (!responseBytes) return "unknown";

    const innerBytes = (responseBytes.value as forge.asn1.Asn1[])[0];
    const basicRespDer = (innerBytes.value as forge.asn1.Asn1[])[1];
    if (!basicRespDer) return "unknown";

    const basicResp = forge.asn1.fromDer(basicRespDer.value as string);
    const tbsData = (basicResp.value as forge.asn1.Asn1[])[0];

    return findCertStatus(tbsData.value as forge.asn1.Asn1[]) ?? "unknown";
  } catch {
    return "unknown";
  }
}

function findCertStatus(nodes: forge.asn1.Asn1[]): OCSPStatus | null {
  for (const node of nodes) {
    if (node.type === forge.asn1.Type.SEQUENCE && node.constructed) {
      const children = node.value as forge.asn1.Asn1[];
      const second = children[1];

      if (second?.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC) {
        if (second.type === 0) return "good";
        if (second.type === 1) return "revoked";
        if (second.type === 2) return "unknown";
      }

      const found = findCertStatus(children);
      if (found !== null) return found;
    }
  }
  return null;
}

// ─── Side Effect: HTTP + CRL fallback ────────────────────────────────────────

/**
 * Checks a certificate's revocation status via OCSP with retry and CRL fallback.
 *
 * Flow:
 *   1. Try OCSP with retry
 *   2. If OCSP is unreachable and CRL fallback is enabled, try CRL
 *   3. Return result with raw responseBytes for DSS embedding
 */
export async function checkOCSP(
  cert: forge.pki.Certificate,
  issuerCert: forge.pki.Certificate,
  ocspUrl: string,
  timeoutMs = 8000,
  retryOptions: RetryOptions = DEFAULT_OCSP_RETRY,
  enableCRLFallback = true
): Promise<OCSPResult> {
  let requestBuffer: Buffer;

  try {
    requestBuffer = buildOCSPRequest(cert, issuerCert);
  } catch (err) {
    return {
      status: "unknown",
      message: `Could not build OCSP request: ${(err as Error).message}`,
    };
  }

  // ── Try OCSP with retry ───────────────────────────────────────────────
  let ocspResult: OCSPResult;

  try {
    ocspResult = await withRetry(() => sendOCSPRequest(requestBuffer, ocspUrl, timeoutMs), {
      ...retryOptions,
      // Don't retry if the cert is definitively revoked or unknown
      shouldRetry: (err) =>
        err.message.includes("timeout") || err.message.includes("network") || err.message.includes("fetch"),
    });
  } catch (err) {
    ocspResult = {
      status: "unreachable",
      message: `OCSP failed after retries: ${(err as Error).message}`,
    };
  }

  // ── CRL fallback if OCSP unreachable ──────────────────────────────────
  if (ocspResult.status === "unreachable" && enableCRLFallback) {
    const crlUrl = extractCRLUrl(cert);
    if (crlUrl) {
      const crlResult = await checkCRL(cert, crlUrl, timeoutMs);
      if (crlResult.status !== "unreachable") {
        return {
          ...crlResult,
          message: `[CRL fallback] ${crlResult.message}`,
        };
      }
    }
  }

  return ocspResult;
}

async function sendOCSPRequest(requestBuffer: Buffer, ocspUrl: string, timeoutMs: number): Promise<OCSPResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(ocspUrl, {
      method: "POST",
      headers: { "Content-Type": "application/ocsp-request" },
      body: new Uint8Array(requestBuffer),
      signal: controller.signal,
    });

    if (!response.ok) {
      return {
        status: "unreachable",
        message: `OCSP responder returned HTTP ${response.status}`,
      };
    }

    const responseBytes = Buffer.from(await response.arrayBuffer());
    const status = parseOCSPResponse(responseBytes);

    const messages: Record<OCSPStatus, string> = {
      good: "Certificate is valid and not revoked.",
      revoked: "Certificate has been REVOKED by the issuing CA.",
      unknown: "Certificate status could not be determined.",
      unreachable: "OCSP responder was unreachable.",
    };

    return { status, message: messages[status], responseBytes };
  } catch (err) {
    const isTimeout = (err as Error).name === "AbortError";
    const message = isTimeout
      ? `OCSP check timed out after ${timeoutMs / 1000}s.`
      : `OCSP check failed: ${(err as Error).message}`;

    throw new Error(message);
  } finally {
    clearTimeout(timer);
  }
}
