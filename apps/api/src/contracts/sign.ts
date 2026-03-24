import z from "zod";

export const SignSchema = z.object({
  pdf: z
    .instanceof(File, { message: "PDF file is required." })
    .refine((f) => f.name.toLowerCase().endsWith(".pdf"), "File must be a PDF.")
    .refine((f) => f.size <= 50 * 1024 * 1024, "PDF must be under 50MB."),

  p12: z
    .instanceof(File, { message: "P12 certificate is required." })
    .refine((f) => /\.(p12|pfx)$/i.test(f.name), "Certificate must be a .p12 or .pfx file.")
    .refine((f) => f.size <= 5 * 1024 * 1024, "P12 must be under 5MB."),

  signatureImage: z
    .instanceof(File)
    .refine((f) => f.size <= 2 * 1024 * 1024, "Signature image must be under 2MB.")
    .refine((f) => ["image/png", "image/jpeg"].includes(f.type), "Signature image must be PNG or JPG.")
    .optional(),

  signaturePage: z.coerce.number().int().min(1).optional(),
  signatureX: z.coerce.number().optional(),
  signatureY: z.coerce.number().optional(),
  signatureWidth: z.coerce.number().optional(),
  signatureHeight: z.coerce.number().optional(),
  password: z.string({ required_error: "Password is required." }).min(1, "Password cannot be empty."),
  reason: z.string().optional(),
  location: z.string().optional(),
});
