// Main signing function
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
  RetryOptions,
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
} from "./lib/errors.js";

// Pure utilities — exported for testing and advanced use
export { parseP12, extractCertInfo, extractAIAUrls, validateCertChain } from "./lib/cert-utils.js";
export { buildOCSPRequest, parseOCSPResponse, checkOCSP } from "./lib/ocsp.js";
export { buildTSRequest, extractTSToken, injectTimestampIntoCMS, requestTimestamp } from "./lib/tsa.js";
export { trimDerBuffer, extractSignatureValueFromCMS } from "./lib/signer.js";
export { findByteRange, extractContentsHex } from "./lib/pdf-parser.js";
export { checkCRL, extractCRLUrl } from "./lib/crl.js";
export { appendDSSDictionary, certToDer } from "./lib/dss.js";
export { withRetry, DEFAULT_OCSP_RETRY, DEFAULT_TSA_RETRY } from "./lib/retry.js";
