/**
 * @file pdf-parser.ts
 *
 * Byte-level PDF parser for signature-related structures.
 * Replaces fragile regex-based /ByteRange extraction.
 */

/**
 * Scans a signed PDF buffer for the last /ByteRange entry and returns
 * its four integer values [b0, b1, b2, b3].
 *
 * Why last occurrence: pdflibAddPlaceholder may write a placeholder
 * /ByteRange first; the final signed PDF overwrites it with real values.
 *
 * Performs sanity checks on the values before returning.
 */
export function findByteRange(pdfBuffer: Buffer): [number, number, number, number] | null {
  const marker = Buffer.from("/ByteRange");
  let searchPos = pdfBuffer.length - 1;
  let markerPos = -1;

  // Find last occurrence of /ByteRange
  while (searchPos >= marker.length) {
    const found = pdfBuffer.lastIndexOf(marker, searchPos);
    if (found === -1) break;
    markerPos = found;
    break;
  }

  if (markerPos === -1) return null;

  let pos = markerPos + marker.length;

  // Skip whitespace
  while (pos < pdfBuffer.length && isWhitespace(pdfBuffer[pos])) pos++;

  // Expect '['
  if (pdfBuffer[pos] !== 0x5b) return null;
  pos++;

  const nums: number[] = [];

  while (nums.length < 4 && pos < pdfBuffer.length) {
    // Skip whitespace
    while (pos < pdfBuffer.length && isWhitespace(pdfBuffer[pos])) pos++;

    if (pos >= pdfBuffer.length) break;
    if (pdfBuffer[pos] === 0x5d) break; // ']'

    // Read integer
    let numStr = "";
    while (pos < pdfBuffer.length && isDigit(pdfBuffer[pos])) {
      numStr += String.fromCharCode(pdfBuffer[pos]);
      pos++;
    }

    if (!numStr) break;
    nums.push(parseInt(numStr, 10));
  }

  if (nums.length !== 4) return null;

  const [b0, b1, b2, b3] = nums;

  // Sanity checks
  if (b0 < 0 || b1 <= 0 || b2 <= 0 || b3 <= 0) return null;
  if (b0 + b1 >= b2) return null;
  if (b2 + b3 > pdfBuffer.length) return null;

  return [b0, b1, b2, b3];
}

/**
 * Extracts the hex-encoded /Contents value (the CMS signature bytes)
 * from between the ByteRange segments.
 *
 * The /Contents entry sits between b0+b1 and b2, wrapped in < >.
 */
export function extractContentsHex(pdfBuffer: Buffer, byteRange: [number, number, number, number]): string {
  const [b0, b1, b2] = byteRange;

  // Find '<' after b0+b1
  let start = b0 + b1;
  while (start < b2 && pdfBuffer[start] !== 0x3c) start++; // '<'
  start++; // skip '<'

  // Find '>' before b2
  let end = b2 - 1;
  while (end > start && pdfBuffer[end] !== 0x3e) end--; // '>'

  return pdfBuffer.subarray(start, end).toString("ascii");
}

function isWhitespace(byte: number): boolean {
  return (
    byte === 0x20 || // space
    byte === 0x09 || // tab
    byte === 0x0a || // LF
    byte === 0x0d || // CR
    byte === 0x00 // null
  );
}

function isDigit(byte: number): boolean {
  return byte >= 0x30 && byte <= 0x39;
}
