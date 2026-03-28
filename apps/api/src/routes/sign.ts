import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { signPDF } from "@workspace/pdf-signer";
import { SignSchema } from "../contracts/sign.js";

export const signHandler = new Hono().post("/sign", zValidator("form", SignSchema), async (c) => {
  const {
    pdf,
    p12,
    password,
    reason,
    location,
    signatureImage,
    signaturePage,
    signatureX,
    signatureY,
    signatureWidth,
    signatureHeight,
  } = c.req.valid("form");

  const signatureImageBuffer = signatureImage ? Buffer.from(await signatureImage.arrayBuffer()) : undefined;

  const signaturePosition =
    signaturePage && signatureX !== undefined
      ? {
          page: signaturePage,
          x: signatureX,
          y: signatureY!,
          width: signatureWidth!,
          height: signatureHeight!,
        }
      : undefined;

  const [pdfBuffer, p12Buffer] = await Promise.all([
    pdf.arrayBuffer().then(Buffer.from),
    p12.arrayBuffer().then(Buffer.from),
  ]);

  // ── Sign ──────────────────────────────────────────────────────────────
  try {
    const result = await signPDF({
      pdfBuffer,
      p12Buffer,
      password,
      reason,
      location,
      signatureImage: signatureImageBuffer,
      signaturePosition,
      skipOCSP: true,
      skipTSA: true,
    });

    const filename = pdf.name.replace(/\.pdf$/i, "") + "_signed.pdf";

    return new Response(new Uint8Array(result.signedPdf), {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "X-Signer-Name": encodeURIComponent(result.certInfo.commonName),
        "X-Cert-Organization": encodeURIComponent(result.certInfo.organization),
        "X-OCSP-Status": result.ocspResult.status,
        "X-Timestamped": String(result.timestamped),
        "X-DSS-Added": String(result.dssAdded), // ← add this
        "X-Warnings": encodeURIComponent(JSON.stringify(result.warnings)),
      },
    });
  } catch (err) {
    const message = (err as Error).message ?? "An unexpected error occurred.";
    console.error("[/api/sign] Error:", message);
    return c.json({ error: message }, 422);
  }
});
