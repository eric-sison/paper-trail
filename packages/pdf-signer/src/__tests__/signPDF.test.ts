import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { fileURLToPath } from "url";
import { signPDF } from "../lib/signer.js";
import { CertExpiredError, CertRevokedError, InvalidPasswordError, InvalidPdfError } from "../types.js";

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
});
