/**
 * @file crl.ts
 *
 * CRL (Certificate Revocation List) checking — used as a fallback
 * when the OCSP responder is unreachable.
 *
 * CRL checks are slower than OCSP (download the full list), but provide
 * revocation status even when the OCSP server is down.
 */

import forge from "node-forge";
import type { OCSPResult } from "../types.js";

/**
 * Extracts the CRL distribution point URL from a certificate's
 * cRLDistributionPoints extension (OID 2.5.29.31).
 */
export function extractCRLUrl(cert: forge.pki.Certificate): string | null {
  const crlExt = cert.extensions?.find((e) => e.id === "2.5.29.31" || e.name === "cRLDistributionPoints");

  if (!crlExt?.value) return null;

  try {
    // Parse the extension value as ASN.1
    const asn1 = forge.asn1.fromDer(
      typeof crlExt.value === "string"
        ? crlExt.value
        : forge.asn1.toDer(crlExt.value as forge.asn1.Asn1).getBytes()
    );

    // CRLDistributionPoints ::= SEQUENCE OF DistributionPoint
    // DistributionPoint ::= SEQUENCE { distributionPoint [0] ... }
    // GeneralName [6] uniformResourceIdentifier IA5String
    const url = findUrlInAsn1(asn1);
    if (url) return url;
  } catch {
    // fall through to regex
  }

  // Regex fallback on raw value
  const val = String(crlExt.value);
  const match = val.match(/(https?:\/\/[^\s\x00-\x1f\x86,]+)/i);
  return match?.[1]?.trim() ?? null;
}

function findUrlInAsn1(node: forge.asn1.Asn1): string | null {
  if (node.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && node.type === 6 && !node.constructed) {
    return (node.value as string).replace(/[^\x20-\x7e]/g, "");
  }

  if (node.constructed && Array.isArray(node.value)) {
    for (const child of node.value as forge.asn1.Asn1[]) {
      const found = findUrlInAsn1(child);
      if (found) return found;
    }
  }

  return null;
}

/**
 * Downloads and parses a CRL, checking if the given certificate's serial
 * number appears in the revoked certificates list.
 *
 * Non-blocking — returns 'unreachable' on any network failure so signing
 * can continue with a warning.
 *
 * @param cert      - The certificate to check
 * @param crlUrl    - CRL distribution point URL
 * @param timeoutMs - Request timeout in ms
 */
export async function checkCRL(
  cert: forge.pki.Certificate,
  crlUrl: string,
  timeoutMs = 10000
): Promise<OCSPResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(crlUrl, {
      method: "GET",
      signal: controller.signal,
    });

    if (!response.ok) {
      return {
        status: "unreachable",
        message: `CRL server returned HTTP ${response.status}`,
      };
    }

    const crlBuffer = Buffer.from(await response.arrayBuffer());
    return parseCRLBuffer(cert, crlBuffer);
  } catch (err) {
    const isTimeout = (err as Error).name === "AbortError";
    return {
      status: "unreachable",
      message: isTimeout
        ? `CRL check timed out after ${timeoutMs / 1000}s.`
        : `CRL check failed: ${(err as Error).message}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Parses a DER-encoded CRL and checks if the certificate serial number
 * is in the revoked list.
 *
 * CRL structure (RFC 5280):
 *   CertificateList ::= SEQUENCE {
 *     tbsCertList          TBSCertList,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signatureValue       BIT STRING
 *   }
 *   TBSCertList ::= SEQUENCE {
 *     version              Version OPTIONAL,
 *     signature            AlgorithmIdentifier,
 *     issuer               Name,
 *     thisUpdate           Time,
 *     nextUpdate           Time OPTIONAL,
 *     revokedCertificates  SEQUENCE OF SEQUENCE { ... } OPTIONAL,
 *     ...
 *   }
 */
function parseCRLBuffer(cert: forge.pki.Certificate, crlBuffer: Buffer): OCSPResult {
  try {
    const asn1 = forge.asn1.fromDer(crlBuffer.toString("binary"));
    const certList = asn1.value as forge.asn1.Asn1[];

    if (certList.length < 1) return { status: "unknown", message: "Empty CRL" };

    const tbsCertList = certList[0].value as forge.asn1.Asn1[];
    const certSerialNorm = normalizeSerial(cert.serialNumber);

    // Scan TBSCertList fields for the revokedCertificates SEQUENCE
    for (const field of tbsCertList) {
      if (
        field.type === forge.asn1.Type.SEQUENCE &&
        field.constructed &&
        Array.isArray(field.value) &&
        (field.value as forge.asn1.Asn1[]).length > 0
      ) {
        const firstChild = (field.value as forge.asn1.Asn1[])[0];

        // revokedCertificates is a SEQUENCE OF SEQUENCE
        if (firstChild.type === forge.asn1.Type.SEQUENCE && firstChild.constructed) {
          // This looks like revokedCertificates — scan entries
          for (const entry of field.value as forge.asn1.Asn1[]) {
            if (entry.type !== forge.asn1.Type.SEQUENCE || !entry.constructed) continue;

            const entryFields = entry.value as forge.asn1.Asn1[];
            if (entryFields.length === 0) continue;

            // First field is the serial number INTEGER
            const serialField = entryFields[0];
            if (serialField.type !== forge.asn1.Type.INTEGER) continue;

            const revokedSerial = normalizeSerial(
              Buffer.from(serialField.value as string, "binary").toString("hex")
            );

            if (revokedSerial === certSerialNorm) {
              return {
                status: "revoked",
                message: "Certificate found in CRL — has been revoked.",
                crlBytes: crlBuffer,
              };
            }
          }

          // Scanned all entries — not revoked
          return {
            status: "good",
            message: "Certificate not found in CRL — valid.",
            crlBytes: crlBuffer,
          };
        }
      }
    }

    return {
      status: "unknown",
      message: "Could not locate revokedCertificates in CRL.",
      crlBytes: crlBuffer,
    };
  } catch (err) {
    return {
      status: "unknown",
      message: `Failed to parse CRL: ${(err as Error).message}`,
    };
  }
}

function normalizeSerial(hex: string): string {
  return hex.toLowerCase().replace(/^0+/, "") || "0";
}
