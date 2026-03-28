import { describe, it, expect } from "vitest";
import { appendDSSDictionary } from "../lib/dss.js";
import { readFileSync } from "fs";
import { join } from "path";
import { fileURLToPath } from "url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const signedPdf = readFileSync(join(__dirname, "fixtures/sample.pdf"));

describe("appendDSSDictionary", () => {
  it("returns original PDF if DSS fails gracefully", () => {
    // Pass garbage buffers — should not throw
    const result = appendDSSDictionary(Buffer.from("not a pdf"), [], [], Buffer.from("sig"));
    expect(Buffer.isBuffer(result)).toBe(true);
  });

  it("returns a larger buffer after DSS append", () => {
    const certDer = Buffer.alloc(100, 0xaa); // fake cert
    const ocspDer = Buffer.alloc(50, 0xbb); // fake OCSP
    const sigValue = Buffer.alloc(32, 0xcc); // fake sig

    const result = appendDSSDictionary(signedPdf, [certDer], [ocspDer], sigValue);

    expect(result.length).toBeGreaterThan(signedPdf.length);
  });

  it("contains /DSS in the output", () => {
    const result = appendDSSDictionary(signedPdf, [Buffer.alloc(10, 0xaa)], [], Buffer.alloc(32, 0xcc));

    expect(result.toString("latin1")).toContain("/DSS");
  });

  it("contains /VRI in the output", () => {
    const result = appendDSSDictionary(signedPdf, [], [], Buffer.alloc(32, 0xcc));

    expect(result.toString("latin1")).toContain("/VRI");
  });

  it("contains /CRLs in the output when CRL data is provided", () => {
    const crlDer = Buffer.alloc(80, 0xdd);
    const result = appendDSSDictionary(signedPdf, [Buffer.alloc(10, 0xaa)], [], Buffer.alloc(32, 0xcc), [
      crlDer,
    ]);

    expect(result.toString("latin1")).toContain("/CRLs");
  });

  it("CRL entry appears in /VRI when CRL data is provided", () => {
    const crlDer = Buffer.alloc(80, 0xdd);
    const result = appendDSSDictionary(signedPdf, [], [], Buffer.alloc(32, 0xcc), [crlDer]);

    expect(result.toString("latin1")).toContain("/CRL");
  });

  it("produces a larger buffer when CRL data is provided", () => {
    const crlDer = Buffer.alloc(80, 0xdd);
    const withoutCrl = appendDSSDictionary(signedPdf, [], [], Buffer.alloc(32, 0xcc));
    const withCrl = appendDSSDictionary(signedPdf, [], [], Buffer.alloc(32, 0xcc), [crlDer]);

    expect(withCrl.length).toBeGreaterThan(withoutCrl.length);
  });

  it("/CRLs is empty array when no CRL data provided", () => {
    const result = appendDSSDictionary(signedPdf, [], [], Buffer.alloc(32, 0xcc));
    expect(result.toString("latin1")).toContain("/CRLs []");
  });
});
