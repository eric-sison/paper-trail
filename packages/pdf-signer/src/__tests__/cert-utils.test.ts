import { describe, it, expect } from "vitest";
import { extractAIAUrls } from "../lib/cert-utils.js";
import type forge from "node-forge";

// Helper to build a mock forge certificate with a fake AIA extension
function makeCertWithAIA(aiaValue: string): forge.pki.Certificate {
  return {
    extensions: [
      {
        id: "1.3.6.1.5.5.7.1.1",
        value: aiaValue,
      },
    ],
  } as unknown as forge.pki.Certificate;
}

describe("extractAIAUrls", () => {
  it("returns null for both when no AIA extension present", () => {
    const cert = { extensions: [] } as unknown as forge.pki.Certificate;
    expect(extractAIAUrls(cert)).toEqual({ ocspUrl: null, tsaUrl: null });
  });

  it("returns null for both when AIA extension has no value", () => {
    const cert = {
      extensions: [{ id: "1.3.6.1.5.5.7.1.1", value: "" }],
    } as unknown as forge.pki.Certificate;
    expect(extractAIAUrls(cert)).toEqual({ ocspUrl: null, tsaUrl: null });
  });

  it("extracts OCSP URL from AIA extension", () => {
    const cert = makeCertWithAIA("1.3.6.1.5.5.7.48.1\x86http://ocsp.npki.gov.ph");
    const { ocspUrl } = extractAIAUrls(cert);
    expect(ocspUrl).toBe("http://ocsp.npki.gov.ph");
  });

  it("extracts TSA URL from AIA extension", () => {
    const cert = makeCertWithAIA("1.3.6.1.5.5.7.48.3\x86http://tsa.npki.gov.ph");
    const { tsaUrl } = extractAIAUrls(cert);
    expect(tsaUrl).toBe("http://tsa.npki.gov.ph");
  });

  it("extracts both OCSP and TSA URLs when both present", () => {
    const cert = makeCertWithAIA(
      "1.3.6.1.5.5.7.48.1\x86http://ocsp.npki.gov.ph\x00" + "1.3.6.1.5.5.7.48.3\x86http://tsa.npki.gov.ph"
    );
    expect(extractAIAUrls(cert)).toEqual({
      ocspUrl: "http://ocsp.npki.gov.ph",
      tsaUrl: "http://tsa.npki.gov.ph",
    });
  });

  it("returns null for missing URL when only one is present", () => {
    const cert = makeCertWithAIA("1.3.6.1.5.5.7.48.1\x86http://ocsp.npki.gov.ph");
    const { tsaUrl } = extractAIAUrls(cert);
    expect(tsaUrl).toBeNull();
  });
});
