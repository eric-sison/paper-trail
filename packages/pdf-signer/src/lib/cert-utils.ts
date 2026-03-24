/**
 * @file cert-utils.ts
 *
 * Everything depends on this utility file. Its job is:
 * - Take a `.p12` buffer + password
 * - Parse it using `node-forge`
 * - Return the private key, certificate chain, and other useful cert info
 *   (name, org, OCSP URL, TSA URL, expiry)
 *
 * When you download your `.p12` from PNPKI, it contains 3 things bundled together:
 * - Private key     → the secret used to create the signature
 * - Certificate     → the owner's public identity (name, org, serial number) signed by PNPKI
 * - Cert chain      → the intermediate/root CA certificates that prove PNPKI vouches for you
 */

import forge from "node-forge";
import type { CertInfo, ParsedP12 } from "../types.js";
import { InvalidPasswordError, InvalidP12Error } from "../types.js";

/**
 * Parses a PKCS#12 (.p12 / .pfx) file and extracts its contents.
 *
 * @param p12Buffer - Raw binary contents of the .p12 file as a Node.js Buffer
 * @param password  - Password set by the user when downloading from the PNPKI portal
 *
 * @returns ParsedP12 containing privateKey, certChain, and certInfo
 *
 * @throws {InvalidPasswordError} If the password is wrong
 * @throws {InvalidP12Error} If the file is not a valid PKCS#12 container
 */
export function parseP12(p12Buffer: Buffer, password: string): ParsedP12 {
  let p12: forge.pkcs12.Pkcs12Pfx;

  try {
    const p12Asn1 = forge.asn1.fromDer(forge.util.createBuffer(p12Buffer.toString("binary")));
    p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);
  } catch (err) {
    const msg = (err as Error).message ?? "";
    if (
      msg.includes("password") ||
      msg.includes("passphrase") ||
      msg.includes("decrypt") ||
      msg.includes("integrity")
    ) {
      throw new InvalidPasswordError();
    }
    throw new InvalidP12Error();
  }

  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });

  const keyBag =
    keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0] ??
    p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag]?.[0];

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });

  const certChain = (certBags[forge.pki.oids.certBag] ?? []).map((b) => b.cert!).filter(Boolean);

  if (!keyBag?.key) throw new InvalidP12Error();
  if (certChain.length === 0) throw new InvalidP12Error();

  const privateKey = keyBag.key;
  const certInfo = extractCertInfo(certChain[0]);

  return { privateKey, certChain, certInfo };
}

/**
 * Extracts human-readable metadata from a forge certificate object.
 *
 * Reads the certificate's Subject Distinguished Name fields (CN, O, OU, email),
 * validity dates, issuer, and AIA extension URLs (OCSP + TSA).
 *
 * @param cert - A parsed forge certificate, typically certChain[0]
 * @returns CertInfo
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
  };
}

/**
 * Extracts OCSP and TSA URLs from a certificate's Authority Information Access
 * (AIA) extension (OID 1.3.6.1.5.5.7.1.1).
 *
 * node-forge does not parse AIA into a structured object, so we extract
 * the URLs by matching the OIDs followed by the http(s) URL in the raw string.
 *
 * The \x86 byte is a context tag that precedes URLs in the raw DER value.
 * Including it in the exclusion set prevents the OCSP URL from bleeding
 * into the next access description.
 *
 * @param cert - A parsed forge certificate to inspect
 * @returns Object with ocspUrl and tsaUrl (both nullable)
 */
export function extractAIAUrls(cert: forge.pki.Certificate): {
  ocspUrl: string | null;
  tsaUrl: string | null;
} {
  const aiaExt = cert.extensions?.find((e) => e.id === "1.3.6.1.5.5.7.1.1");

  if (!aiaExt?.value) return { ocspUrl: null, tsaUrl: null };

  const val = String(aiaExt.value);

  // OCSP OID: 1.3.6.1.5.5.7.48.1
  // \x86 is the context tag byte preceding URLs in raw DER — stop matching there
  const ocspMatch = val.match(/1\.3\.6\.1\.5\.5\.7\.48\.1[^h]*(https?:\/\/[^\s\x00-\x1f\x86,]+)/i);

  // TSA OID: 1.3.6.1.5.5.7.48.3
  const tsaMatch = val.match(/1\.3\.6\.1\.5\.5\.7\.48\.3[^h]*(https?:\/\/[^\s\x00-\x1f\x86,]+)/i);

  return {
    ocspUrl: ocspMatch?.[1]?.trim() ?? null,
    tsaUrl: tsaMatch?.[1]?.trim() ?? null,
  };
}
