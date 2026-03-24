import { describe, it, expect } from "vitest";
import forge from "node-forge";
import { extractTSToken, injectTimestampIntoCMS } from "../lib/tsa.js";
import { TSAError } from "../types.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Builds a minimal DER-encoded TimeStampResp.
 * statusCode 0 = granted, 2 = rejection
 */
function buildFakeTSResponse(statusCode: number, includeToken: boolean): Buffer {
  const status = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, String.fromCharCode(statusCode)),
  ]);

  const nodes: forge.asn1.Asn1[] = [status];

  if (includeToken) {
    // Minimal fake ContentInfo (TimeStampToken)
    const token = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OID,
        false,
        forge.asn1.oidToDer("1.2.840.113549.1.7.2").getBytes() // signedData
      ),
    ]);
    nodes.push(token);
  }

  const tsResp = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, nodes);

  return Buffer.from(forge.asn1.toDer(tsResp).getBytes(), "binary");
}

/**
 * Builds a minimal DER-encoded CMS SignedData with empty unsignedAttrs.
 * Just enough structure for injectTimestampIntoCMS to navigate.
 */
function buildFakeCMS(): Buffer {
  // SignerInfo
  const signerInfo = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    // version
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, "\x01"),
    // sid (issuerAndSerialNumber placeholder)
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []),
    // digestAlgorithm
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []),
    // signatureAlgorithm
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []),
    // signature OCTET STRING
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, "fakesig"),
  ]);

  // signerInfos SET
  const signerInfos = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [signerInfo]);

  // SignedData
  const signedData = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    // version
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, "\x01"),
    // digestAlgorithms
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, []),
    // encapContentInfo
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []),
    signerInfos,
  ]);

  // ContentInfo
  const contentInfo = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.OID,
      false,
      forge.asn1.oidToDer("1.2.840.113549.1.7.2").getBytes()
    ),
    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [signedData]),
  ]);

  return Buffer.from(forge.asn1.toDer(contentInfo).getBytes(), "binary");
}

// ─── extractTSToken ───────────────────────────────────────────────────────────

describe("extractTSToken", () => {
  it("returns token buffer when status is granted (0)", () => {
    const response = buildFakeTSResponse(0, true);
    const token = extractTSToken(response);
    expect(Buffer.isBuffer(token)).toBe(true);
    expect(token.length).toBeGreaterThan(0);
  });

  it("returns token buffer when status is grantedWithMods (1)", () => {
    const response = buildFakeTSResponse(1, true);
    const token = extractTSToken(response);
    expect(Buffer.isBuffer(token)).toBe(true);
  });

  it("throws TSAError when status is rejection (2)", () => {
    const response = buildFakeTSResponse(2, false);
    expect(() => extractTSToken(response)).toThrowError(TSAError);
  });

  it("throws TSAError when token is missing from response", () => {
    const response = buildFakeTSResponse(0, false);
    expect(() => extractTSToken(response)).toThrowError(TSAError);
  });
});

// ─── injectTimestampIntoCMS ───────────────────────────────────────────────────

describe("injectTimestampIntoCMS", () => {
  it("injects timestamp token as unsigned attribute", () => {
    const cmsDer = buildFakeCMS();
    const tsTokenDer = buildFakeTSResponse(0, true);

    const patched = injectTimestampIntoCMS(cmsDer, tsTokenDer);

    // Patched CMS should be larger than original
    expect(patched.length).toBeGreaterThan(cmsDer.length);
    expect(Buffer.isBuffer(patched)).toBe(true);
  });

  it("calling twice adds two unsigned attributes", () => {
    const cmsDer = buildFakeCMS();
    const tsTokenDer = buildFakeTSResponse(0, true);

    const patched1 = injectTimestampIntoCMS(cmsDer, tsTokenDer);
    const patched2 = injectTimestampIntoCMS(patched1, tsTokenDer);

    expect(patched2.length).toBeGreaterThan(patched1.length);
  });

  it("returns a valid DER buffer that can be re-parsed by forge", () => {
    const cmsDer = buildFakeCMS();
    const tsTokenDer = buildFakeTSResponse(0, true);
    const patched = injectTimestampIntoCMS(cmsDer, tsTokenDer);

    // Should not throw
    expect(() => forge.asn1.fromDer(patched.toString("binary"))).not.toThrow();
  });
});
