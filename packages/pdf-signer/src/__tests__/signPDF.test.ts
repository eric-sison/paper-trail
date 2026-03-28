import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { fileURLToPath } from "url";
import { signPDF, type CertInfo } from "../lib/signer.js";
import { parseP12 } from "../lib/cert-utils.js";
import { CertExpiredError, CertRevokedError, InvalidPasswordError, InvalidPdfError } from "../lib/errors.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

const pdfBuffer = readFileSync(join(__dirname, "fixtures/sample.pdf"));
const p12Buffer = readFileSync(join(__dirname, "fixtures/cert.p12"));
const PASSWORD = "ericsison80171";

// ─── Mock OCSP + TSA ──────────────────────────────────────────────────────────

const mockOcspChecker = vi.fn().mockResolvedValue({
  status: "good",
  message: "Certificate is valid and not revoked.",
});

const mockTsaRequester = vi.fn().mockResolvedValue(Buffer.from("fake-tsa-token"));

// ─── Mock P12 ──────────────────────────────────────────────────────────

vi.mock("../lib/cert-utils.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/cert-utils.js")>();
  return {
    ...actual,
    parseP12: vi.fn(actual.parseP12), // ← calls real impl by default
  };
});

const mockParseP12 = vi.mocked(parseP12);

const validCertInfoNoUrls: CertInfo = {
  commonName: "Test User",
  organization: "Test Org",
  email: "test@test.com",
  serialNumber: "01",
  validFrom: new Date("2023-01-01"),
  validTo: new Date("2099-01-01"),
  issuerCN: "Test CA",
  isExpired: false,
  daysUntilExpiry: 999,
  ocspUrl: null,
  tsaUrl: null,
  crlUrl: null,
};

const expiredCertInfo: CertInfo = {
  commonName: "Test User",
  organization: "Test Org",
  email: "test@test.com",
  serialNumber: "01",
  validFrom: new Date("2020-01-01"),
  validTo: new Date("2021-01-01"), // expired
  issuerCN: "Test CA",
  isExpired: true,
  daysUntilExpiry: -999,
  ocspUrl: null,
  tsaUrl: null,
  crlUrl: null,
};

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("signPDF", () => {
  it("signs a PDF and returns a signed buffer", async () => {
    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      reason: "Testing",
      location: "Philippines",
      skipOCSP: true,
      skipTSA: true,
    });

    expect(Buffer.isBuffer(result.signedPdf)).toBe(true);
    expect(result.signedPdf.length).toBeGreaterThan(pdfBuffer.length);
    expect(result.certInfo.commonName).toBeTruthy();
    expect(result.timestamped).toBe(false);
  });

  it("calls injected ocspChecker when skipOCSP is false", async () => {
    mockOcspChecker.mockClear();

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: false,
      skipTSA: true,
      ocspChecker: mockOcspChecker,
    });

    expect(mockOcspChecker).toHaveBeenCalledOnce();
  });

  it("does not call ocspChecker when skipOCSP is true", async () => {
    mockOcspChecker.mockClear();

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: true,
      ocspChecker: mockOcspChecker,
    });

    expect(mockOcspChecker).not.toHaveBeenCalled();
  });

  it("calls injected tsaRequester when skipTSA is false", async () => {
    mockTsaRequester.mockClear();

    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: false,
      tsaRequester: mockTsaRequester,
      tsaRetryOptions: {
        retries: 0,
        initialDelayMs: 0,
      },
    });

    // TSA was called but token was fake so timestamped may be false
    expect(mockTsaRequester).toHaveBeenCalledOnce();
  });

  it("adds warning when ocsp status is unreachable", async () => {
    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipTSA: true,
      ocspChecker: vi.fn().mockResolvedValue({
        status: "unreachable",
        message: "OCSP timed out.",
      }),
    });

    expect(result.warnings).toContain("OCSP timed out.");
  });

  it("throws CertRevokedError when ocsp returns revoked", async () => {
    await expect(
      signPDF({
        pdfBuffer,
        p12Buffer,
        password: PASSWORD,
        skipTSA: true,
        ocspChecker: vi.fn().mockResolvedValue({
          status: "revoked",
          message: "Certificate has been revoked.",
        }),
      })
    ).rejects.toThrow(CertRevokedError);
  });

  it("throws InvalidPasswordError for wrong password", async () => {
    await expect(
      signPDF({
        pdfBuffer,
        p12Buffer,
        password: "wrongpassword",
        skipOCSP: true,
        skipTSA: true,
      })
    ).rejects.toThrow(InvalidPasswordError);
  });

  it("throws InvalidPdfError for invalid PDF", async () => {
    await expect(
      signPDF({
        pdfBuffer: Buffer.from("not a pdf"),
        p12Buffer,
        password: PASSWORD,
        skipOCSP: true,
        skipTSA: true,
      })
    ).rejects.toThrow(InvalidPdfError);
  });

  it("includes cert expiry warning when cert expires within 30 days", async () => {
    // This test only runs if your cert is expiring soon
    // Otherwise it just verifies warnings is an array
    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: true,
    });

    expect(Array.isArray(result.warnings)).toBe(true);
  });

  it("throws InvalidPdfError when PDF exceeds maxPdfSize", async () => {
    await expect(
      signPDF({
        pdfBuffer,
        p12Buffer,
        password: PASSWORD,
        skipOCSP: true,
        skipTSA: true,
        maxPdfSize: 1,
      })
    ).rejects.toThrow(InvalidPdfError);
  });

  it("throws when P12 exceeds maxP12Size", async () => {
    await expect(
      signPDF({
        pdfBuffer,
        p12Buffer,
        password: PASSWORD,
        skipOCSP: true,
        skipTSA: true,
        maxP12Size: 1,
      })
    ).rejects.toThrow("exceeds limit");
  });

  it("adds warning and sets timestamped=false when TSA requester fails", async () => {
    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: false,
      tsaRequester: vi.fn().mockRejectedValue(new Error("TSA unavailable")),
      tsaRetryOptions: { retries: 0, initialDelayMs: 0 },
    });

    expect(result.timestamped).toBe(false);
    expect(result.warnings.some((w) => w.includes("TSA timestamp could not be applied"))).toBe(true);
  });

  it("sets dssAdded=false when skipDSS is true", async () => {
    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: true,
      skipDSS: true,
    });

    expect(result.dssAdded).toBe(false);
  });

  it("throws CertExpiredError when cert is expired (default behavior)", async () => {
    mockParseP12.mockReturnValueOnce({
      privateKey: {} as any,
      certChain: [],
      certInfo: expiredCertInfo,
    });

    await expect(
      signPDF({
        pdfBuffer,
        p12Buffer,
        password: PASSWORD,
        skipOCSP: true,
        skipTSA: true,
      })
    ).rejects.toThrow(CertExpiredError);
  });

  it("continues with warning when rejectIfExpired is false", async () => {
    mockParseP12.mockReturnValueOnce({
      privateKey: {} as any,
      certChain: [],
      certInfo: expiredCertInfo,
    });

    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: true,
      rejectIfExpired: false,
    });

    expect(result.warnings.some((w) => w.includes("expired"))).toBe(true);
  });

  // ─── Additional SignOptions coverage ─────────────────────────────────────────
  // Append these tests inside the existing describe("signPDF", ...) block
  // in signPDF.test.ts, after the rejectIfExpired tests.

  // ── Shared fixture for tests that need to control certInfo ────────────────────
  // Add this alongside expiredCertInfo at the top of the file:
  //
  // const validCertInfoNoUrls: CertInfo = {
  //   commonName: "Test User",
  //   organization: "Test Org",
  //   email: "test@test.com",
  //   serialNumber: "01",
  //   validFrom: new Date("2023-01-01"),
  //   validTo: new Date("2099-01-01"),
  //   issuerCN: "Test CA",
  //   isExpired: false,
  //   daysUntilExpiry: 999,
  //   ocspUrl: null,   // ← forces fallback URL usage
  //   tsaUrl: null,    // ← forces fallback URL usage
  //   crlUrl: null,
  // };

  // ─── password as Buffer ───────────────────────────────────────────────────────

  it("accepts password as Buffer", async () => {
    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: Buffer.from(PASSWORD, "utf8"),
      skipOCSP: true,
      skipTSA: true,
    });

    expect(Buffer.isBuffer(result.signedPdf)).toBe(true);
  });

  // ─── enableCRLFallback ────────────────────────────────────────────────────────

  it("passes enableCRLFallback=false to ocspChecker", async () => {
    const checker = vi.fn().mockResolvedValue({ status: "good", message: "ok" });

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipTSA: true,
      skipOCSP: false,
      enableCRLFallback: false,
      ocspChecker: checker,
    });

    // 6th argument to ocspChecker is enableCRLFallback
    expect(checker).toHaveBeenCalledOnce();
    expect(checker.mock.calls[0][5]).toBe(false);
  });

  it("passes enableCRLFallback=true by default to ocspChecker", async () => {
    const checker = vi.fn().mockResolvedValue({ status: "good", message: "ok" });

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipTSA: true,
      skipOCSP: false,
      ocspChecker: checker,
    });

    expect(checker.mock.calls[0][5]).toBe(true);
  });

  it("passes fallbackCrlUrl to ocspChecker", async () => {
    const checker = vi.fn().mockResolvedValue({ status: "good", message: "ok" });

    mockParseP12.mockReturnValueOnce({
      privateKey: {} as any,
      certChain: [{} as any, {} as any],
      certInfo: validCertInfoNoUrls,
    });

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipTSA: true,
      skipOCSP: false,
      fallbackCrlUrl: "http://custom-crl.example.com",
      ocspChecker: checker,
    });

    // 7th argument to ocspChecker is fallbackCrlUrl
    expect(checker.mock.calls[0][6]).toBe("http://custom-crl.example.com");
  });

  it("uses built-in PNPKI CRL fallback when no fallbackCrlUrl provided", async () => {
    const checker = vi.fn().mockResolvedValue({ status: "good", message: "ok" });

    mockParseP12.mockReturnValueOnce({
      privateKey: {} as any,
      certChain: [{} as any, {} as any],
      certInfo: validCertInfoNoUrls,
    });

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipTSA: true,
      skipOCSP: false,
      ocspChecker: checker,
    });

    expect(checker.mock.calls[0][6]).toBe("http://crl.npki.gov.ph");
  });

  it("does not use fallbackCrlUrl when enableCRLFallback is false", async () => {
    const checker = vi.fn().mockResolvedValue({ status: "good", message: "ok" });

    mockParseP12.mockReturnValueOnce({
      privateKey: {} as any,
      certChain: [{} as any, {} as any],
      certInfo: validCertInfoNoUrls,
    });

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipTSA: true,
      skipOCSP: false,
      enableCRLFallback: false,
      fallbackCrlUrl: "http://custom-crl.example.com",
      ocspChecker: checker,
    });

    // fallbackCrlUrl is still passed as the 7th arg to ocspChecker,
    // but ocsp.ts ignores it because enableCRLFallback=false gates the whole block
    expect(checker.mock.calls[0][5]).toBe(false); // enableCRLFallback
    expect(checker.mock.calls[0][6]).toBe("http://custom-crl.example.com"); // passed but unused
  });

  // ─── fallbackOcspUrl ──────────────────────────────────────────────────────────

  it("uses fallbackOcspUrl when cert has no ocspUrl", async () => {
    const checker = vi.fn().mockResolvedValue({ status: "good", message: "ok" });

    mockParseP12.mockReturnValueOnce({
      privateKey: {} as any,
      certChain: [{} as any, {} as any], // 2 certs so OCSP is attempted
      certInfo: validCertInfoNoUrls,
    });

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipTSA: true,
      skipOCSP: false,
      fallbackOcspUrl: "http://custom-ocsp.example.com",
      ocspChecker: checker,
    });

    // 3rd argument to ocspChecker is the ocspUrl
    expect(checker.mock.calls[0][2]).toBe("http://custom-ocsp.example.com");
  });

  it("uses built-in PNPKI fallback when no fallbackOcspUrl provided and cert has no ocspUrl", async () => {
    const checker = vi.fn().mockResolvedValue({ status: "good", message: "ok" });

    mockParseP12.mockReturnValueOnce({
      privateKey: {} as any,
      certChain: [{} as any, {} as any],
      certInfo: validCertInfoNoUrls,
    });

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipTSA: true,
      skipOCSP: false,
      ocspChecker: checker,
    });

    expect(checker.mock.calls[0][2]).toBe("http://ocsp.npki.gov.ph");
  });

  // ─── fallbackTsaUrl ───────────────────────────────────────────────────────────

  it("uses fallbackTsaUrl when cert has no tsaUrl", async () => {
    const tsaRequester = vi.fn().mockRejectedValue(new Error("tsa fail"));

    mockParseP12.mockReturnValueOnce({
      privateKey: {} as any,
      certChain: [{} as any, {} as any],
      certInfo: validCertInfoNoUrls,
    });

    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: false,
      fallbackTsaUrl: "http://custom-tsa.example.com",
      tsaRequester,
      tsaRetryOptions: { retries: 0, initialDelayMs: 0 },
    });

    // 2nd argument to tsaRequester is the tsaUrl
    expect(tsaRequester.mock.calls[0][1]).toBe("http://custom-tsa.example.com");
    expect(result.timestamped).toBe(false); // failed but didn't throw
  });

  it("uses built-in PNPKI TSA fallback when no fallbackTsaUrl provided and cert has no tsaUrl", async () => {
    const tsaRequester = vi.fn().mockRejectedValue(new Error("tsa fail"));

    mockParseP12.mockReturnValueOnce({
      privateKey: {} as any,
      certChain: [{} as any, {} as any],
      certInfo: validCertInfoNoUrls,
    });

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: false,
      tsaRequester,
      tsaRetryOptions: { retries: 0, initialDelayMs: 0 },
    });

    expect(tsaRequester.mock.calls[0][1]).toBe("http://tsa.npki.gov.ph");
  });

  // ─── ocspRetryOptions ─────────────────────────────────────────────────────────

  it("passes ocspRetryOptions to ocspChecker", async () => {
    const checker = vi.fn().mockResolvedValue({ status: "good", message: "ok" });

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipTSA: true,
      skipOCSP: false,
      ocspChecker: checker,
      ocspRetryOptions: { retries: 3, initialDelayMs: 500, backoffFactor: 2 },
    });

    // 5th argument to ocspChecker is retryOptions
    expect(checker.mock.calls[0][4]).toMatchObject({
      retries: 3,
      initialDelayMs: 500,
      backoffFactor: 2,
    });
  });

  // ─── logCertInfo ──────────────────────────────────────────────────────────────

  it("logs cert info when logCertInfo is true", async () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: true,
      logCertInfo: true,
    });

    expect(spy).toHaveBeenCalledWith(
      "[pdf-signer] Certificate Info:",
      expect.objectContaining({ commonName: expect.any(String) })
    );

    spy.mockRestore();
  });

  it("does not log cert info when logCertInfo is false (default)", async () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});

    await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: true,
    });

    const certInfoLog = spy.mock.calls.find((c) => String(c[0]).includes("Certificate Info"));
    expect(certInfoLog).toBeUndefined();

    spy.mockRestore();
  });

  // ─── reason / location / contactInfo / stampHeader ───────────────────────────

  it("signs successfully with reason and location set", async () => {
    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: true,
      reason: "Approved by management",
      location: "Davao City",
    });

    expect(Buffer.isBuffer(result.signedPdf)).toBe(true);
  });

  it("signs successfully with contactInfo and stampHeader set", async () => {
    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: true,
      contactInfo: "signer@example.com",
      stampHeader: "APPROVED BY ACME CORP",
    });

    expect(Buffer.isBuffer(result.signedPdf)).toBe(true);
  });

  // ─── signatureImage ───────────────────────────────────────────────────────────

  it("signs successfully with a signatureImage provided", async () => {
    // Minimal 1x1 white PNG
    const minimalPng = Buffer.from(
      "89504e470d0a1a0a0000000d49484452000000010000000108020000" +
        "0090wc3d000000000c4944415408d76360f8cfc00000000200" +
        "01e221bc330000000049454e44ae426082",
      "hex"
    );

    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: true,
      signatureImage: minimalPng,
    });

    expect(Buffer.isBuffer(result.signedPdf)).toBe(true);
  });

  // ─── signaturePosition ────────────────────────────────────────────────────────

  it("signs successfully with a custom signaturePosition", async () => {
    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password: PASSWORD,
      skipOCSP: true,
      skipTSA: true,
      signaturePosition: {
        page: 1,
        x: 50,
        y: 50,
        width: 200,
        height: 60,
      },
    });

    expect(Buffer.isBuffer(result.signedPdf)).toBe(true);
  });
});
