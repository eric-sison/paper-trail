/**
 * @file ocsp.ts
 *
 * Handles certificate revocation checking via OCSP (Online Certificate Status Protocol).
 *
 * Before signing, we ask PNPKI's OCSP server: "Is this certificate still valid?"
 * The check is non-blocking — if the server is unreachable, signing continues
 * with a warning rather than failing completely.
 *
 * This file is split into three layers:
 *
 *   Pure (no side effects, fully testable):
 *     - buildOCSPRequest()   — builds the DER-encoded OCSP request
 *     - parseOCSPResponse()  — parses the DER-encoded OCSP response
 *
 *   Side effects (HTTP, testable via injection):
 *     - checkOCSP()          — sends the request and returns OCSPResult
 */

import forge from "node-forge";
import type { OCSPResult, OCSPStatus } from "../types.js";

// ─── Pure: Request Builder ────────────────────────────────────────────────────

/**
 * Builds a DER-encoded OCSP request for a single certificate (RFC 6960).
 *
 * The request identifies the certificate to check using a CertID structure:
 *
 *   OCSPRequest
 *     └── tbsRequest
 *           └── requestList
 *                 └── Request
 *                       └── CertID
 *                             ├── hashAlgorithm  — SHA-1
 *                             ├── issuerNameHash — SHA-1 of issuer's Distinguished Name (DER)
 *                             ├── issuerKeyHash  — SHA-1 of issuer's public key bytes
 *                             └── serialNumber   — serial number of the cert being checked
 *
 * We use the ISSUER's name and key (not the signing cert's) because the OCSP
 * server indexes certificates by who issued them, not by their own public key.
 *
 * @param cert       - The certificate whose revocation status we want to check
 * @param issuerCert - The CA certificate that issued `cert` (from the cert chain)
 * @returns DER-encoded OCSP request as a Buffer
 */
export function buildOCSPRequest(cert: forge.pki.Certificate, issuerCert: forge.pki.Certificate): Buffer {
  // 1. issuerNameHash — SHA-1 of the issuer's Distinguished Name in DER format
  const issuerDNDer = forge.asn1.toDer(forge.pki.distinguishedNameToAsn1(issuerCert.subject)).getBytes();
  const issuerNameHash = forge.md.sha1.create().update(issuerDNDer).digest().getBytes();

  // 2. issuerKeyHash — SHA-1 of the issuer's public key bytes
  const issuerKeyAsn1 = forge.pki.publicKeyToAsn1(issuerCert.publicKey as forge.pki.PublicKey);
  const spkiValue = (issuerKeyAsn1 as forge.asn1.Asn1).value as forge.asn1.Asn1[];
  const keyBytes = forge.asn1.toDer(spkiValue[1]).getBytes().slice(1);
  const issuerKeyHash = forge.md.sha1.create().update(keyBytes).digest().getBytes();

  // 3. serialNumber — the cert's serial number as raw binary bytes
  const serialHex = cert.serialNumber;
  const serialBytes = Buffer.from(serialHex.length % 2 === 0 ? serialHex : "0" + serialHex, "hex").toString("binary");

  // SHA-1 AlgorithmIdentifier
  const sha1AlgId = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer("1.3.14.3.2.26").getBytes()
    ),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ""),
  ]);

  // CertID
  const certId = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    sha1AlgId,
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, issuerNameHash),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, issuerKeyHash),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, serialBytes),
  ]);

  // OCSPRequest
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
 *
 * Navigates:
 *   OCSPResponse → responseBytes → BasicOCSPResponse → tbsResponseData → responses[0] → certStatus
 *
 * certStatus is a CONTEXT-SPECIFIC tag:
 *   [0] good    — certificate is valid
 *   [1] revoked — certificate has been revoked
 *   [2] unknown — status could not be determined
 *
 * Returns 'unknown' on any parse error rather than throwing.
 *
 * @param responseBuffer - Raw DER bytes from the OCSP HTTP response
 * @returns OCSPStatus string
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

/**
 * Recursively searches ASN.1 nodes for a SingleResponse pattern.
 *
 * A SingleResponse is a SEQUENCE where children[1] is a CONTEXT_SPECIFIC
 * certStatus tag ([0] good, [1] revoked, [2] unknown).
 *
 * We search recursively because the depth of nesting varies between
 * OCSP implementations — some wrap responses in extra layers.
 */
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

      // Recurse into nested sequences
      const found = findCertStatus(children);
      if (found !== null) return found;
    }
  }
  return null;
}

// ─── Side Effect: HTTP ────────────────────────────────────────────────────────

/**
 * Checks a certificate's revocation status against PNPKI's OCSP responder.
 *
 * Non-blocking — if the OCSP server is unreachable (common outside Philippine
 * government networks), returns 'unreachable' rather than throwing, so signing
 * can continue with a warning.
 *
 * @param cert       - The signing certificate to check
 * @param issuerCert - The issuing CA certificate (certChain[1])
 * @param ocspUrl    - OCSP responder URL (read from cert's AIA extension)
 * @param timeoutMs  - How long to wait before giving up (default 8 seconds)
 * @returns OCSPResult
 */
export async function checkOCSP(
  cert: forge.pki.Certificate,
  issuerCert: forge.pki.Certificate,
  ocspUrl: string,
  timeoutMs = 8000
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

    const responseBuffer = Buffer.from(await response.arrayBuffer());
    const status = parseOCSPResponse(responseBuffer);

    const messages: Record<OCSPStatus, string> = {
      good: "Certificate is valid and not revoked.",
      revoked: "Certificate has been REVOKED by the issuing CA.",
      unknown: "Certificate status could not be determined.",
      unreachable: "OCSP responder was unreachable.",
    };

    return { status, message: messages[status] };
  } catch (err) {
    const isTimeout = (err as Error).name === "AbortError";
    return {
      status: "unreachable",
      message: isTimeout
        ? `OCSP check timed out after ${timeoutMs / 1000}s.`
        : `OCSP check failed: ${(err as Error).message}`,
    };
  } finally {
    clearTimeout(timer);
  }
}
