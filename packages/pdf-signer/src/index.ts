// Main entry point
export { signPDF } from "./lib/signer.js";

// Types
export type {
  SignOptions,
  SignResult,
  SignaturePosition,
  CertInfo,
  OCSPResult,
  OCSPStatus,
  OCSPChecker,
  TSARequester,
  ParsedP12,
} from "./types.js";

// Errors
export {
  PdfSignerError,
  InvalidPasswordError,
  CertExpiredError,
  CertRevokedError,
  InvalidP12Error,
  InvalidPdfError,
  OCSPError,
  TSAError,
} from "./types.js";

// Pure utilities — exported for testing and advanced use cases
export { parseP12, extractCertInfo, extractAIAUrls } from "./lib/cert-utils.js";
export { buildOCSPRequest, parseOCSPResponse, checkOCSP } from "./lib/ocsp.js";
export { buildTSRequest, extractTSToken, injectTimestampIntoCMS, requestTimestamp } from "./lib/tsa.js";
export { trimDerBuffer, extractSignatureValueFromCMS } from "./lib/signer.js";
