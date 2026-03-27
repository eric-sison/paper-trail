import { describe, it, expect } from "vitest";
import { trimDerBuffer } from "../lib/signer.js";
import { findByteRange, extractContentsHex } from "../lib/pdf-parser.js";
import { extractSignatureValueFromCMS } from "../lib/signer.js";
import forge from "node-forge";

describe("trimDerBuffer", () => {
  it("returns buffer as-is if not a SEQUENCE (0x30)", () => {
    const buf = Buffer.from([0x02, 0x01, 0x01]);
    expect(trimDerBuffer(buf)).toEqual(buf);
  });

  it("trims zero padding from a short-form DER buffer", () => {
    const real = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]);
    const padded = Buffer.concat([real, Buffer.alloc(5)]);
    expect(trimDerBuffer(padded)).toEqual(real);
  });

  it("handles long-form DER length encoding", () => {
    const content = Buffer.alloc(130, 0xaa);
    const header = Buffer.from([0x30, 0x81, 0x82]);
    const real = Buffer.concat([header, content]);
    const padded = Buffer.concat([real, Buffer.alloc(20)]);
    expect(trimDerBuffer(padded)).toEqual(real);
  });

  it("returns buffer as-is if too short", () => {
    const buf = Buffer.from([0x30, 0x01]);
    expect(trimDerBuffer(buf)).toEqual(buf);
  });
});

describe("findByteRange", () => {
  function buildFakePdf(b0: number, b1: number, b2: number, b3: number): Buffer {
    const byteRange = `/ByteRange [${b0} ${b1} ${b2} ${b3}]`;
    const padding = Buffer.alloc(b2 + b3);
    return Buffer.concat([Buffer.from(byteRange), padding]);
  }

  it("returns null when /ByteRange is absent", () => {
    expect(findByteRange(Buffer.from("no byte range here"))).toBeNull();
  });

  it("parses a valid /ByteRange", () => {
    // Buffer must be at least b2+b3 bytes long to pass sanity check
    const totalSize = 200 + 300 + 100; // b2 + b3 + header
    const pdf = Buffer.alloc(totalSize);
    Buffer.from("/ByteRange [0 100 200 300]").copy(pdf);
    const result = findByteRange(pdf);
    expect(result).not.toBeNull();
    expect(result![0]).toBe(0);
    expect(result![1]).toBe(100);
    expect(result![2]).toBe(200);
    expect(result![3]).toBe(300);
  });

  it("rejects /ByteRange where b0+b1 >= b2", () => {
    // 0 + 200 = 200, which is NOT < 200
    const pdf = Buffer.from("/ByteRange [0 200 200 100]" + " ".repeat(500));
    expect(findByteRange(pdf)).toBeNull();
  });
});

describe("extractContentsHex", () => {
  it("extracts hex content between angle brackets", () => {
    // Layout: [4 bytes segment1] <aabbcc> [5 bytes segment2]
    // b0=0, b1=4, b2=12 (4 + 8 chars for "<aabbcc>"), b3=5
    const segment1 = Buffer.alloc(4, 0xff);
    const contents = Buffer.from("<aabbcc>");
    const segment2 = Buffer.alloc(5, 0x00);
    const pdf = Buffer.concat([segment1, contents, segment2]);
    const byteRange: [number, number, number, number] = [0, 4, 4 + contents.length, 5];
    expect(extractContentsHex(pdf, byteRange)).toBe("aabbcc");
  });

  it("returns empty string when no angle brackets found", () => {
    const pdf = Buffer.alloc(20, 0x41); // all 'A', no < or >
    const byteRange: [number, number, number, number] = [0, 4, 12, 5];
    // start ends up past b2, so subarray is empty
    expect(extractContentsHex(pdf, byteRange)).toBe("");
  });

  it("handles an empty contents placeholder", () => {
    const segment1 = Buffer.alloc(4, 0xff);
    const contents = Buffer.from("<>");
    const segment2 = Buffer.alloc(5, 0x00);
    const pdf = Buffer.concat([segment1, contents, segment2]);
    const byteRange: [number, number, number, number] = [0, 4, 4 + contents.length, 5];
    expect(extractContentsHex(pdf, byteRange)).toBe("");
  });
});

describe("extractSignatureValueFromCMS", () => {
  function buildFakeCMSWithSignature(sigValue: string): Buffer {
    const signerInfo = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, "\x01"),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, sigValue),
    ]);

    const signerInfos = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [signerInfo]);

    const signedData = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false, "\x01"),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, []),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, []),
      signerInfos,
    ]);

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

  it("extracts signature value bytes from a CMS structure", () => {
    const sigValue = "fakesignaturebytes";
    const cms = buildFakeCMSWithSignature(sigValue);
    const result = extractSignatureValueFromCMS(cms);
    expect(Buffer.isBuffer(result)).toBe(true);
    expect(result.toString("binary")).toBe(sigValue);
  });

  it("returns a non-empty buffer", () => {
    const cms = buildFakeCMSWithSignature("abcdef");
    const result = extractSignatureValueFromCMS(cms);
    expect(result.length).toBeGreaterThan(0);
  });
});
