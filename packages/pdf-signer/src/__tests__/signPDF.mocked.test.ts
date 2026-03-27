import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { fileURLToPath } from "url";

vi.mock("../lib/cert-utils.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/cert-utils.js")>();
  return { ...actual, parseP12: vi.fn() };
});

import { signPDF } from "../lib/signer.js";
import * as certUtils from "../lib/cert-utils.js";
import { CertExpiredError } from "../lib/errors.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const pdfBuffer = readFileSync(join(__dirname, "fixtures/sample.pdf"));
const p12Buffer = readFileSync(join(__dirname, "fixtures/cert.p12"));

const expiredCertInfo = {
  commonName: "Test User",
  organization: "Test Org",
  email: "test@example.com",
  serialNumber: "01",
  validFrom: new Date("2020-01-01"),
  validTo: new Date("2020-12-31"),
  issuerCN: "Test CA",
  isExpired: true,
  daysUntilExpiry: -100,
  ocspUrl: null,
  tsaUrl: null,
  crlUrl: null,
};

describe("signPDF — mocked internals", () => {
  it("throws CertExpiredError when certificate is expired", async () => {
    vi.mocked(certUtils.parseP12).mockReturnValueOnce({
      privateKey: {} as any,
      certChain: [{} as any],
      certInfo: expiredCertInfo,
    });

    await expect(
      signPDF({
        pdfBuffer,
        p12Buffer,
        password: "any",
        skipOCSP: true,
        skipTSA: true,
      })
    ).rejects.toThrow(CertExpiredError);
  });
});
