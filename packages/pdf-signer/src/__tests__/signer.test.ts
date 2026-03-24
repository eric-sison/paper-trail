import { describe, it, expect } from "vitest";
import { trimDerBuffer } from "../lib/signer.js";

describe("trimDerBuffer", () => {
  it("returns buffer as-is if not a SEQUENCE (0x30)", () => {
    const buf = Buffer.from([0x02, 0x01, 0x01]);
    expect(trimDerBuffer(buf)).toEqual(buf);
  });

  it("trims zero padding from a short-form DER buffer", () => {
    // SEQUENCE { INTEGER 1 } = 30 03 02 01 01
    // padded with zeros to 10 bytes
    const real = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]);
    const padded = Buffer.concat([real, Buffer.alloc(5)]);
    expect(trimDerBuffer(padded)).toEqual(real);
  });

  it("handles long-form DER length encoding", () => {
    // SEQUENCE with length > 127 — use 0x81 0xNN encoding
    const content = Buffer.alloc(130, 0xaa);
    const header = Buffer.from([0x30, 0x81, 0x82]); // 0x82 = 130
    const real = Buffer.concat([header, content]);
    const padded = Buffer.concat([real, Buffer.alloc(20)]);
    expect(trimDerBuffer(padded)).toEqual(real);
  });

  it("returns buffer as-is if too short", () => {
    const buf = Buffer.from([0x30, 0x01]);
    expect(trimDerBuffer(buf)).toEqual(buf);
  });
});
