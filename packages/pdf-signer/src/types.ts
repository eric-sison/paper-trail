import type forge from "node-forge";

// ─── Base Error ───────────────────────────────────────────────────────────────

export class PdfSignerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PdfSignerError";
  }
}

// ─── Specific Errors ──────────────────────────────────────────────────────────

export class InvalidPasswordError extends PdfSignerError {
  constructor() {
    super("Incorrect P12 password.");
    this.name = "InvalidPasswordError";
  }
}

export class CertExpiredError extends PdfSignerError {
  constructor(expiredOn: string) {
    super(`Certificate expired on ${expiredOn}.`);
    this.name = "CertExpiredError";
  }
}

export class CertRevokedError extends PdfSignerError {
  constructor() {
    super("Certificate has been revoked by the PNPKI CA.");
    this.name = "CertRevokedError";
  }
}

export class InvalidP12Error extends PdfSignerError {
  constructor() {
    super("The certificate file is invalid or corrupted.");
    this.name = "InvalidP12Error";
  }
}

export class InvalidPdfError extends PdfSignerError {
  constructor() {
    super("The PDF file is invalid or corrupted.");
    this.name = "InvalidPdfError";
  }
}

export class OCSPError extends PdfSignerError {
  constructor(message: string) {
    super(`OCSP check failed: ${message}`);
    this.name = "OCSPError";
  }
}

export class TSAError extends PdfSignerError {
  constructor(message: string) {
    super(`TSA request failed: ${message}`);
    this.name = "TSAError";
  }
}

// ─── Certificate Types ────────────────────────────────────────────────────────

export interface CertInfo {
  commonName: string;
  organization: string;
  email: string;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
  issuerCN: string;
  isExpired: boolean;
  daysUntilExpiry: number;
  ocspUrl: string | null;
  tsaUrl: string | null;
}

// ─── OCSP Types ───────────────────────────────────────────────────────────────

export type OCSPStatus = "good" | "revoked" | "unknown" | "unreachable";

export interface OCSPResult {
  status: OCSPStatus;
  message: string;
  revokedAt?: Date;
}

/**
 * Injectable OCSP checker function.
 * Accepts the signing cert, issuer cert, OCSP URL, and timeout.
 * Returns an OCSPResult.
 * Replace with a mock in tests.
 */
export type OCSPChecker = (
  cert: forge.pki.Certificate,
  issuerCert: forge.pki.Certificate,
  ocspUrl: string,
  timeoutMs?: number
) => Promise<OCSPResult>;

// ─── TSA Types ────────────────────────────────────────────────────────────────

/**
 * Injectable TSA requester function.
 * Accepts the signature value bytes, TSA URL, and timeout.
 * Returns the raw DER-encoded TimeStampToken buffer.
 * Replace with a mock in tests.
 */
export type TSARequester = (signatureValueBytes: Buffer, tsaUrl: string, timeoutMs?: number) => Promise<Buffer>;

// ─── Signature Position ───────────────────────────────────────────────────────

export interface SignaturePosition {
  /** 1-based page number */
  page: number;
  /** X coordinate from left edge of page in PDF points */
  x: number;
  /** Y coordinate from bottom edge of page in PDF points */
  y: number;
  /** Width of the signature box in PDF points */
  width: number;
  /** Height of the signature box in PDF points */
  height: number;
}

// ─── Sign Options ─────────────────────────────────────────────────────────────

export interface SignOptions {
  /** Raw bytes of the PDF file to sign */
  pdfBuffer: Buffer;
  /** Raw bytes of the PNPKI .p12 certificate file */
  p12Buffer: Buffer;
  /** Password used to decrypt the .p12 file */
  password: string;
  /** Reason for signing */
  reason?: string;
  /** Physical location of the signer */
  location?: string;
  /** Optional PNG or JPG image to embed in the signature stamp */
  signatureImage?: Buffer;
  /** Where to draw the stamp — defaults to bottom-right of last page */
  signaturePosition?: SignaturePosition;
  /**
   * Injectable OCSP checker — defaults to the real checkOCSP implementation.
   * Pass a mock in tests to avoid hitting the real OCSP server.
   */
  ocspChecker?: OCSPChecker;
  /**
   * Injectable TSA requester — defaults to the real requestTimestamp implementation.
   * Pass a mock in tests to avoid hitting the real TSA server.
   */
  tsaRequester?: TSARequester;
  /** Skip OCSP check entirely */
  skipOCSP?: boolean;
  /** Skip TSA timestamp entirely */
  skipTSA?: boolean;
  /** OCSP request timeout in ms — defaults to 8000 */
  ocspTimeoutMs?: number;
  /** TSA request timeout in ms — defaults to 10000 */
  tsaTimeoutMs?: number;
}

// ─── Sign Result ──────────────────────────────────────────────────────────────

export interface SignResult {
  /** The signed PDF as a Buffer */
  signedPdf: Buffer;
  /** Metadata extracted from the signing certificate */
  certInfo: CertInfo;
  /** Result of the OCSP revocation check */
  ocspResult: OCSPResult;
  /** Whether a TSA timestamp was successfully embedded */
  timestamped: boolean;
  /** Non-fatal warnings */
  warnings: string[];
}

// ─── P12 Parse Result ─────────────────────────────────────────────────────────

export interface ParsedP12 {
  privateKey: forge.pki.PrivateKey;
  certChain: forge.pki.Certificate[];
  certInfo: CertInfo;
}
