import { describe, it, expect } from "vitest";
import { parseOCSPResponse } from "../lib/ocsp.js";
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
      ? [forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.GENERALIZEDTIME, false, "20240101000000Z")]
      : ""
  );

  const singleResponse = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []),
    certStatus,
  ]);

  const responses = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [singleResponse]);

  const tbsResponseData = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [responses]);

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

  const responseStatus = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.ENUMERATED, false, "\x00");

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
