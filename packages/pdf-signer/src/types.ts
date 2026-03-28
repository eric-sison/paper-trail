import type forge from "node-forge";

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
  crlUrl: string | null;
}

// ─── OCSP Types ───────────────────────────────────────────────────────────────

export type OCSPStatus = "good" | "revoked" | "unknown" | "unreachable";

export interface OCSPResult {
  status: OCSPStatus;
  message: string;
  revokedAt?: Date;
  /** Raw DER bytes of the OCSP response — used for embedding in DSS */
  responseBytes?: Buffer;
  /** Raw DER bytes of the CRL response — used for DSS embedding when OCSP is unreachable */
  crlBytes?: Buffer;
}

/**
 * Injectable OCSP checker function.
 * Replace with a mock in tests to avoid network calls.
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
 * Replace with a mock in tests to avoid network calls.
 */
export type TSARequester = (
  signatureValueBytes: Buffer,
  tsaUrl: string,
  timeoutMs?: number
) => Promise<Buffer>;

// ─── Retry Options ────────────────────────────────────────────────────────────

export interface RetryOptions {
  retries: number;
  initialDelayMs: number;
  backoffFactor?: number;
  shouldRetry?: (err: Error) => boolean;
}

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
  /**
   * Password used to decrypt the .p12 file.
   * Pass as Buffer for best-effort memory wiping after use.
   * Note: JavaScript strings cannot be reliably wiped from memory.
   */
  password: string | Buffer;
  /** Reason for signing */
  reason?: string;
  /** Physical location of the signer */
  location?: string;
  /** Optional PNG or JPG image to embed in the signature stamp */
  signatureImage?: Buffer;
  /** Where to draw the stamp — defaults to bottom-right of last page */
  signaturePosition?: SignaturePosition;
  /**
   * Injectable OCSP checker — defaults to the real checkOCSP.
   * Pass a mock in tests to avoid hitting the real OCSP server.
   */
  ocspChecker?: OCSPChecker;
  /**
   * Injectable TSA requester — defaults to the real requestTimestamp.
   * Pass a mock in tests to avoid hitting the real TSA server.
   */
  tsaRequester?: TSARequester;
  /**
   * If true (default), throw CertExpiredError when the cert is expired.
   * If false, log a warning and continue signing.
   */
  rejectIfExpired?: boolean;
  /** Skip OCSP check entirely */
  skipOCSP?: boolean;
  /** Skip TSA timestamp entirely */
  skipTSA?: boolean;
  /** Skip DSS dictionary (PAdES-B-LT) — set true to get PAdES-B-T only */
  skipDSS?: boolean;
  /** Enable CRL fallback when OCSP is unreachable (default true) */
  enableCRLFallback?: boolean;
  /** OCSP request timeout in ms (default 8000) */
  ocspTimeoutMs?: number;
  /** TSA request timeout in ms (default 10000) */
  tsaTimeoutMs?: number;
  /** OCSP retry options */
  ocspRetryOptions?: RetryOptions;
  /** TSA retry options */
  tsaRetryOptions?: RetryOptions;
  /**
   * Maximum PDF size in bytes (default 100MB).
   * PDFs larger than this are rejected to prevent memory exhaustion.
   */
  maxPdfSize?: number;
  /**
   * Maximum P12 size in bytes (default 5MB).
   */
  maxP12Size?: number;
  /** Fallback OCSP URL if not in cert AIA */
  fallbackOcspUrl?: string;
  /** Fallback TSA URL if not in cert AIA */
  fallbackTsaUrl?: string;
  /** Header text shown on the visible stamp (default "DIGITALLY SIGNED BY PNPKI") */
  stampHeader?: string;
  /** Contact info for the PDF signature dictionary (default: cert email) */
  contactInfo?: string;
  /** If true, logs certificate info to console after parsing the P12 (default false) */
  logCertInfo?: boolean;
}

// ─── Sign Result ──────────────────────────────────────────────────────────────

export interface SignResult {
  /** The signed PDF as a Buffer, ready to send to the client */
  signedPdf: Buffer;
  /** Metadata extracted from the signing certificate */
  certInfo: CertInfo;
  /** Result of the OCSP revocation check */
  ocspResult: OCSPResult;
  /** Whether a TSA timestamp was successfully embedded */
  timestamped: boolean;
  /** Whether a DSS dictionary (PAdES-B-LT) was successfully appended */
  dssAdded: boolean;
  /** Non-fatal warnings */
  warnings: string[];
}

// ─── P12 Parse Result ─────────────────────────────────────────────────────────

export interface ParsedP12 {
  privateKey: forge.pki.PrivateKey;
  certChain: forge.pki.Certificate[];
  certInfo: CertInfo;
}
