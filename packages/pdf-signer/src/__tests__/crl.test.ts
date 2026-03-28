import { describe, it, expect, vi, afterEach } from "vitest";
import forge from "node-forge";
import { extractCRLUrl, checkCRL } from "../lib/crl.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Builds a minimal DER-encoded CRL containing the given revoked serials.
 * An empty array produces a CRL with no revokedCertificates, which causes
 * parseCRLBuffer to return "unknown".
 */
function buildFakeCRL(revokedSerials: string[]): Buffer {
  const revokedEntries = revokedSerials.map((serial) => {
    const serialBytes = Buffer.from(serial.replace(/^0+/, "") || "00", "hex").toString("binary");
    return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, serialBytes),
    ]);
  });

  const tbsFields: forge.asn1.Asn1[] = [];
  if (revokedEntries.length > 0) {
    tbsFields.push(
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, revokedEntries)
    );
  }

  const tbsCertList = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SEQUENCE,
    true,
    tbsFields
  );
  const certList = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    tbsCertList,
  ]);

  return Buffer.from(forge.asn1.toDer(certList).getBytes(), "binary");
}

function makeCert(serialNumber: string): forge.pki.Certificate {
  return { serialNumber, extensions: [] } as unknown as forge.pki.Certificate;
}

function mockFetchWithCRL(crlBuffer: Buffer): void {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      arrayBuffer: vi
        .fn()
        .mockResolvedValue(
          crlBuffer.buffer.slice(crlBuffer.byteOffset, crlBuffer.byteOffset + crlBuffer.byteLength)
        ),
    })
  );
}

// ─── extractCRLUrl ────────────────────────────────────────────────────────────

describe("extractCRLUrl", () => {
  it("returns null when extensions array is empty", () => {
    const cert = { extensions: [] } as unknown as forge.pki.Certificate;
    expect(extractCRLUrl(cert)).toBeNull();
  });

  it("returns null when extensions is undefined", () => {
    const cert = {} as unknown as forge.pki.Certificate;
    expect(extractCRLUrl(cert)).toBeNull();
  });

  it("returns null when CRL extension has no value", () => {
    const cert = {
      extensions: [{ id: "2.5.29.31", value: "" }],
    } as unknown as forge.pki.Certificate;
    expect(extractCRLUrl(cert)).toBeNull();
  });

  it("extracts URL via regex fallback from a plain string value", () => {
    const cert = {
      extensions: [{ id: "2.5.29.31", value: "http://crl.example.com/crl.crl" }],
    } as unknown as forge.pki.Certificate;
    expect(extractCRLUrl(cert)).toBe("http://crl.example.com/crl.crl");
  });

  it("matches by extension name when id is absent", () => {
    const cert = {
      extensions: [{ name: "cRLDistributionPoints", value: "http://crl.example.com/crl.crl" }],
    } as unknown as forge.pki.Certificate;
    expect(extractCRLUrl(cert)).toBe("http://crl.example.com/crl.crl");
  });

  it("extracts URL from ASN.1 DER-encoded value via context-specific [6] node", () => {
    const url = "http://crl.example.com/sub.crl";
    // Build a GeneralName [6] (uniformResourceIdentifier) wrapping the URL
    const urlNode = forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 6, false, url);
    const derValue = forge.asn1.toDer(urlNode).getBytes();
    const cert = {
      extensions: [{ id: "2.5.29.31", value: derValue }],
    } as unknown as forge.pki.Certificate;
    expect(extractCRLUrl(cert)).toBe(url);
  });
});

// ─── checkCRL ─────────────────────────────────────────────────────────────────

describe("checkCRL", () => {
  it("returns 'unreachable' on network error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network failure")));
    const result = await checkCRL(makeCert("deadbeef"), "http://crl.example.com");
    expect(result.status).toBe("unreachable");
    expect(result.message).toContain("network failure");
  });

  it("returns 'unreachable' on AbortError (timeout)", async () => {
    const err = Object.assign(new Error("aborted"), { name: "AbortError" });
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(err));
    const result = await checkCRL(makeCert("deadbeef"), "http://crl.example.com", 1);
    expect(result.status).toBe("unreachable");
    expect(result.message).toContain("timed out");
  });

  it("returns 'unreachable' when server responds with non-OK status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 503, statusText: "Service Unavailable" })
    );
    const result = await checkCRL(makeCert("deadbeef"), "http://crl.example.com");
    expect(result.status).toBe("unreachable");
    expect(result.message).toContain("503");
  });

  it("returns 'good' when cert serial is not in the CRL", async () => {
    const crl = buildFakeCRL(["cafebabe"]);
    mockFetchWithCRL(crl);
    const result = await checkCRL(makeCert("deadbeef"), "http://crl.example.com");
    expect(result.status).toBe("good");
  });

  it("returns 'revoked' when cert serial is found in the CRL", async () => {
    const crl = buildFakeCRL(["deadbeef"]);
    mockFetchWithCRL(crl);
    const result = await checkCRL(makeCert("deadbeef"), "http://crl.example.com");
    expect(result.status).toBe("revoked");
  });

  it("returns 'revoked' with leading-zero normalisation (cert serial 00deadbeef vs CRL deadbeef)", async () => {
    const crl = buildFakeCRL(["deadbeef"]);
    mockFetchWithCRL(crl);
    // forge sometimes stores serial with a leading zero byte
    const result = await checkCRL(makeCert("00deadbeef"), "http://crl.example.com");
    expect(result.status).toBe("revoked");
  });

  it("returns 'unknown' when CRL has no revokedCertificates field", async () => {
    const crl = buildFakeCRL([]); // empty tbsCertList
    mockFetchWithCRL(crl);
    const result = await checkCRL(makeCert("deadbeef"), "http://crl.example.com");
    expect(result.status).toBe("unknown");
  });

  it("returns 'unknown' for a garbage CRL body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: vi.fn().mockResolvedValue(Buffer.from("not a crl").buffer),
      })
    );
    const result = await checkCRL(makeCert("deadbeef"), "http://crl.example.com");
    expect(result.status).toBe("unknown");
  });

  it("returns crlBytes on good status", async () => {
    const crl = buildFakeCRL(["cafebabe"]);
    mockFetchWithCRL(crl);
    const result = await checkCRL(makeCert("deadbeef"), "http://crl.example.com");
    expect(result.status).toBe("good");
    expect(Buffer.isBuffer(result.crlBytes)).toBe(true);
    expect(result.crlBytes!.length).toBeGreaterThan(0);
  });

  it("returns crlBytes on revoked status", async () => {
    const crl = buildFakeCRL(["deadbeef"]);
    mockFetchWithCRL(crl);
    const result = await checkCRL(makeCert("deadbeef"), "http://crl.example.com");
    expect(result.status).toBe("revoked");
    expect(Buffer.isBuffer(result.crlBytes)).toBe(true);
  });

  it("does not return crlBytes when unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network failure")));
    const result = await checkCRL(makeCert("deadbeef"), "http://crl.example.com");
    expect(result.status).toBe("unreachable");
    expect(result.crlBytes).toBeUndefined();
  });
});
