import { describe, it, expect, beforeAll } from "vitest";
import { parseOCSPResponse, buildOCSPRequest } from "../lib/ocsp.js";
import forge from "node-forge";

function buildFakeOCSPResponse(certStatusTag: 0 | 1 | 2): Buffer {
  // certStatus context tags:
  //   [0] good    — primitive NULL
  //   [1] revoked — constructed (wraps RevokedInfo SEQUENCE per RFC 6960)
  //   [2] unknown — primitive NULL
  const isConstructed = certStatusTag === 1;

  const certStatus = forge.asn1.create(
    forge.asn1.Class.CONTEXT_SPECIFIC,
    certStatusTag,
    isConstructed,
    isConstructed
      ? [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.GENERALIZEDTIME,
            false,
            "20240101000000Z"
          ),
        ]
      : ""
  );

  const singleResponse = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []),
    certStatus,
  ]);

  const responses = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    singleResponse,
  ]);

  const tbsResponseData = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    responses,
  ]);

  const basicOCSPResponse = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    tbsResponseData,
  ]);

  const basicOCSPDer = forge.asn1.toDer(basicOCSPResponse).getBytes();

  const responseBytes = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer("1.3.6.1.5.5.7.48.1.1").getBytes()
    ),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, basicOCSPDer),
  ]);

  const responseBytesWrapper = forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [responseBytes]);

  const responseStatus = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.ENUMERATED,
    false,
    "\x00"
  );

  const ocspResponse = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    responseStatus,
    responseBytesWrapper,
  ]);

  return Buffer.from(forge.asn1.toDer(ocspResponse).getBytes(), "binary");
}

describe("parseOCSPResponse", () => {
  it("returns 'good' for certStatus [0]", () => {
    expect(parseOCSPResponse(buildFakeOCSPResponse(0))).toBe("good");
  });

  it("returns 'revoked' for certStatus [1]", () => {
    expect(parseOCSPResponse(buildFakeOCSPResponse(1))).toBe("revoked");
  });

  it("returns 'unknown' for certStatus [2]", () => {
    expect(parseOCSPResponse(buildFakeOCSPResponse(2))).toBe("unknown");
  });

  it("returns 'unknown' for empty buffer", () => {
    expect(parseOCSPResponse(Buffer.alloc(0))).toBe("unknown");
  });

  it("returns 'unknown' for garbage input", () => {
    expect(parseOCSPResponse(Buffer.from("not a valid DER buffer"))).toBe("unknown");
  });
});

// ─── buildOCSPRequest ─────────────────────────────────────────────────────────

describe("buildOCSPRequest", () => {
  let cert: forge.pki.Certificate;
  let issuerCert: forge.pki.Certificate;

  beforeAll(() => {
    // Generate minimal certs for testing — 1024-bit is enough for unit tests
    const caKeys = forge.pki.rsa.generateKeyPair(1024);
    issuerCert = forge.pki.createCertificate();
    issuerCert.publicKey = caKeys.publicKey;
    issuerCert.serialNumber = "01";
    issuerCert.validity.notBefore = new Date();
    issuerCert.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    issuerCert.setSubject([{ name: "commonName", value: "Test CA" }]);
    issuerCert.setIssuer([{ name: "commonName", value: "Test CA" }]);
    issuerCert.sign(caKeys.privateKey);

    const certKeys = forge.pki.rsa.generateKeyPair(1024);
    cert = forge.pki.createCertificate();
    cert.publicKey = certKeys.publicKey;
    cert.serialNumber = "0deadbeef";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    cert.setSubject([{ name: "commonName", value: "Test User" }]);
    cert.setIssuer([{ name: "commonName", value: "Test CA" }]);
    cert.sign(caKeys.privateKey);
  });

  it("returns a Buffer", () => {
    expect(Buffer.isBuffer(buildOCSPRequest(cert, issuerCert))).toBe(true);
  });

  it("produces a non-empty valid DER SEQUENCE parseable by forge", () => {
    const req = buildOCSPRequest(cert, issuerCert);
    expect(req.length).toBeGreaterThan(0);
    expect(() => forge.asn1.fromDer(req.toString("binary"))).not.toThrow();
  });

  it("contains the SHA-1 OID (1.3.14.3.2.26) used for CertID hashes", () => {
    const req = buildOCSPRequest(cert, issuerCert);
    const sha1OidDer = forge.asn1.oidToDer("1.3.14.3.2.26").getBytes();
    expect(req.toString("binary")).toContain(sha1OidDer);
  });

  it("produces the same output for the same inputs (deterministic)", () => {
    const req1 = buildOCSPRequest(cert, issuerCert);
    const req2 = buildOCSPRequest(cert, issuerCert);
    expect(req1.equals(req2)).toBe(true);
  });
});
