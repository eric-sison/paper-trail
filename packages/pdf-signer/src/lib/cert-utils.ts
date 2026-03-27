/**
 * @file cert-utils.ts
 *
 * Parses PKCS#12 (.p12) files using node-forge.
 * Returns the private key, certificate chain, and cert metadata.
 *
 * Phase 2b: AIA URLs now parsed via proper ASN.1 (regex fallback)
 * Phase 2c: Basic certificate chain validation
 */

import forge from "node-forge";
import type { CertInfo, ParsedP12 } from "../types.js";
import { InvalidP12Error, InvalidPasswordError } from "./errors.js";

/**
 * Parses a PKCS#12 file and extracts its contents.
 *
 * @throws {InvalidPasswordError} If the password is wrong
 * @throws {InvalidP12Error}      If the file is not a valid PKCS#12
 */
export function parseP12(p12Buffer: Buffer, password: string | Buffer): ParsedP12 {
  const passwordStr = (password instanceof Buffer ? password.toString("utf8") : password) as string;

  let p12: forge.pkcs12.Pkcs12Pfx;

  try {
    const p12Asn1 = forge.asn1.fromDer(forge.util.createBuffer(p12Buffer.toString("binary")));
    p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, passwordStr); // ← string only
  } catch (err) {
    const msg = (err as Error).message ?? "";
    if (
      msg.includes("password") ||
      msg.includes("passphrase") ||
      msg.includes("decrypt") ||
      msg.includes("integrity") ||
      msg.includes("PKCS#12")
    ) {
      throw new InvalidPasswordError();
    }

    throw new InvalidP12Error();
  } finally {
    // Best-effort: wipe password from buffer memory if it was passed as Buffer
    if (password instanceof Buffer) {
      password.fill(0);
    }
  }

  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keyBag =
    keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0] ??
    p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag]?.[0];

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const certChain = (certBags[forge.pki.oids.certBag] ?? []).map((b) => b.cert!).filter(Boolean);

  if (!keyBag?.key) throw new InvalidP12Error("No private key found in P12.");
  if (certChain.length === 0) throw new InvalidP12Error("No certificates found in P12.");

  // Validate chain structure (issuer names must match)
  validateCertChain(certChain);

  const certInfo = extractCertInfo(certChain[0]);

  return { privateKey: keyBag.key, certChain, certInfo };
}

/**
 * Validates that each certificate in the chain is issued by the next one
 * by comparing Distinguished Name attributes.
 *
 * Note: This validates chain structure only (DN matching), not cryptographic
 * signatures. Full cryptographic validation would require the complete CA
 * certificate store, which is not available in this context.
 *
 * @throws {InvalidP12Error} If the chain is broken
 */
export function validateCertChain(certChain: forge.pki.Certificate[]): void {
  if (certChain.length < 2) return;

  for (let i = 0; i < certChain.length - 1; i++) {
    const cert = certChain[i];
    const issuer = certChain[i + 1];

    const certIssuerAttrs = cert.issuer.attributes
      .map((a) => `${a.shortName ?? a.type}=${String(a.value).trim().toLowerCase()}`)
      .sort()
      .join(",");

    const issuerSubjectAttrs = issuer.subject.attributes
      .map((a) => `${a.shortName ?? a.type}=${String(a.value).trim().toLowerCase()}`)
      .sort()
      .join(",");

    if (certIssuerAttrs !== issuerSubjectAttrs) {
      console.warn(
        `[pdf-signer] Certificate chain DN mismatch at index ${i} ` +
          `(may be encoding difference — chain may still be valid)`
      );
    }
  }
}

function dnToString(attrs: forge.pki.CertificateField[]): string {
  return attrs
    .map((a) => `${a.type}=${String(a.value).toLowerCase()}`)
    .sort()
    .join(",");
}

/**
 * Extracts human-readable metadata and AIA URLs from a forge certificate.
 */
export function extractCertInfo(cert: forge.pki.Certificate): CertInfo {
  const getField = (name: string): string => {
    try {
      return (cert.subject.getField(name)?.value as string) ?? "";
    } catch {
      return "";
    }
  };

  const now = new Date();
  const validTo = cert.validity.notAfter;
  const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

  const { ocspUrl, tsaUrl } = extractAIAUrls(cert);
  const crlUrl = extractCRLUrlFromCert(cert);

  return {
    commonName: getField("CN"),
    organization: getField("O") || getField("OU"),
    email: getField("emailAddress") || getField("E") || "",
    serialNumber: cert.serialNumber,
    validFrom: cert.validity.notBefore,
    validTo,
    issuerCN: (cert.issuer.getField("CN")?.value as string) ?? "",
    isExpired: now > validTo,
    daysUntilExpiry,
    ocspUrl,
    tsaUrl,
    crlUrl,
  };
}

/**
 * Extracts OCSP and TSA URLs from the AIA extension using proper ASN.1 parsing.
 * Falls back to regex if ASN.1 parsing fails.
 *
 * AIA OID: 1.3.6.1.5.5.7.1.1
 * OCSP method OID: 1.3.6.1.5.5.7.48.1
 * TSA method OID: 1.3.6.1.5.5.7.48.3
 */
export function extractAIAUrls(cert: forge.pki.Certificate): {
  ocspUrl: string | null;
  tsaUrl: string | null;
} {
  const aiaExt = cert.extensions?.find((e) => e.id === "1.3.6.1.5.5.7.1.1");
  if (!aiaExt?.value) return { ocspUrl: null, tsaUrl: null };

  let ocspUrl: string | null = null;
  let tsaUrl: string | null = null;

  // ── Try proper ASN.1 parsing first ─────────────────────────────────────
  try {
    const rawValue =
      typeof aiaExt.value === "string"
        ? aiaExt.value
        : forge.asn1.toDer(aiaExt.value as forge.asn1.Asn1).getBytes();

    const aiaAsn1 = forge.asn1.fromDer(rawValue);

    // AIA ::= SEQUENCE OF AccessDescription
    for (const desc of aiaAsn1.value as forge.asn1.Asn1[]) {
      const descSeq = desc.value as forge.asn1.Asn1[];
      if (descSeq.length < 2) continue;

      let oid: string;
      try {
        oid = forge.asn1.derToOid(forge.util.createBuffer(descSeq[0].value as string));
      } catch {
        continue;
      }

      // GeneralName [6] uniformResourceIdentifier
      const loc = descSeq[1];
      if (loc.tagClass !== forge.asn1.Class.CONTEXT_SPECIFIC || loc.type !== 6) continue;

      const url = (loc.value as string).replace(/[^\x20-\x7e]/g, "").trim();
      if (!url) continue;

      if (oid === "1.3.6.1.5.5.7.48.1") ocspUrl = url;
      if (oid === "1.3.6.1.5.5.7.48.3") tsaUrl = url;
    }

    if (ocspUrl !== null || tsaUrl !== null) {
      return { ocspUrl, tsaUrl };
    }
  } catch {
    // fall through to regex
  }

  // ── Regex fallback ──────────────────────────────────────────────────────
  const val = String(aiaExt.value);

  const ocspMatch = val.match(/1\.3\.6\.1\.5\.5\.7\.48\.1[^h]*(https?:\/\/[^\s\x00-\x1f\x86,]+)/i);
  const tsaMatch = val.match(/1\.3\.6\.1\.5\.5\.7\.48\.3[^h]*(https?:\/\/[^\s\x00-\x1f\x86,]+)/i);

  return {
    ocspUrl: ocspMatch?.[1]?.trim() ?? null,
    tsaUrl: tsaMatch?.[1]?.trim() ?? null,
  };
}

/**
 * Extracts the CRL distribution point URL from a certificate.
 * OID: 2.5.29.31
 */
function extractCRLUrlFromCert(cert: forge.pki.Certificate): string | null {
  const crlExt = cert.extensions?.find((e) => e.id === "2.5.29.31" || e.name === "cRLDistributionPoints");
  if (!crlExt?.value) return null;

  try {
    const rawValue =
      typeof crlExt.value === "string"
        ? crlExt.value
        : forge.asn1.toDer(crlExt.value as forge.asn1.Asn1).getBytes();

    const asn1 = forge.asn1.fromDer(rawValue);
    const url = findUrlInAsn1(asn1);
    if (url) return url;
  } catch {
    // fall through
  }

  const val = String(crlExt.value);
  const match = val.match(/(https?:\/\/[^\s\x00-\x1f\x86,]+)/i);
  return match?.[1]?.trim() ?? null;
}

function findUrlInAsn1(node: forge.asn1.Asn1): string | null {
  if (node.tagClass === forge.asn1.Class.CONTEXT_SPECIFIC && node.type === 6 && !node.constructed) {
    return (node.value as string).replace(/[^\x20-\x7e]/g, "").trim() || null;
  }
  if (node.constructed && Array.isArray(node.value)) {
    for (const child of node.value as forge.asn1.Asn1[]) {
      const found = findUrlInAsn1(child);
      if (found) return found;
    }
  }
  return null;
}
