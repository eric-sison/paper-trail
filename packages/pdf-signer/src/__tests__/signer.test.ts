import { describe, it, expect } from "vitest";
import { trimDerBuffer } from "../lib/signer.js";
import { findByteRange, extractContentsHex } from "../lib/pdf-parser.js";

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
