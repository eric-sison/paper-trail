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
    super("Certificate has been revoked by the issuing CA.");
    this.name = "CertRevokedError";
  }
}

export class InvalidP12Error extends PdfSignerError {
  constructor(detail?: string) {
    super(detail ?? "The certificate file is invalid or corrupted.");
    this.name = "InvalidP12Error";
  }
}

export class InvalidPdfError extends PdfSignerError {
  constructor(detail?: string) {
    super(detail ?? "The PDF file is invalid or corrupted.");
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
