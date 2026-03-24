import { Card, CardContent, CardHeader, CardTitle } from "@workspace/ui/components/card";
import { Alert, AlertDescription } from "@workspace/ui/components/alert";
import { Badge } from "@workspace/ui/components/badge";
import { Button } from "@workspace/ui/components/button";
import { Label } from "@workspace/ui/components/label";
import { Input } from "@workspace/ui/components/input";
import { cn } from "@workspace/ui/lib/utils";
import { useState } from "react";
import { PdfPreview } from "./PdfPreview";

interface SignaturePosition {
  page: number;
  screenX: number;
  screenY: number;
  screenWidth: number;
  screenHeight: number;
  pdfX: number;
  pdfY: number;
  pdfWidth: number;
  pdfHeight: number;
}

type Stage = "idle" | "signing" | "done" | "error";

export function PdfSigner() {
  // Files
  const [pdfFile, setPdfFile] = useState<File | null>(null);
  const [p12File, setP12File] = useState<File | null>(null);
  const [signatureImageFile, setSignatureImageFile] = useState<File | null>(null);
  const [dssAdded, setDssAdded] = useState(false);

  // Credentials
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  // Signature details
  const [reason, setReason] = useState("I have reviewed this document");
  const [location, setLocation] = useState("Philippines");

  // Signature position
  const [signaturePosition, setSignaturePosition] = useState<SignaturePosition | null>(null);

  // UI state
  const [stage, setStage] = useState<Stage>("idle");
  const [warnings, setWarnings] = useState<string[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [signedPdfUrl, setSignedPdfUrl] = useState<string | null>(null);
  const [signedPdfFilename, setSignedPdfFilename] = useState<string | null>(null);

  // Additional state
  const [ocspStatus, setOcspStatus] = useState<string>("unknown");
  const [timestamped, setTimestamped] = useState(false);

  const handleSign = async () => {
    if (!pdfFile || !p12File || !password || !signaturePosition) return;

    setStage("signing");
    setErrorMessage(null);
    setWarnings([]);

    const formData = new FormData();
    formData.append("pdf", pdfFile);
    formData.append("p12", p12File);
    formData.append("password", password);
    formData.append("reason", reason);
    formData.append("location", location);
    if (signatureImageFile) formData.append("signatureImage", signatureImageFile);
    formData.append("signaturePage", String(signaturePosition.page));
    formData.append("signatureX", String(signaturePosition.pdfX));
    formData.append("signatureY", String(signaturePosition.pdfY));
    formData.append("signatureWidth", String(signaturePosition.pdfWidth));
    formData.append("signatureHeight", String(signaturePosition.pdfHeight));

    try {
      const response = await fetch("http://localhost:3852/api/sign", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const body = await response.json().catch(() => ({ error: "Unknown error" }));
        throw new Error(body.error ?? `Server error ${response.status}`);
      }

      const blob = await response.blob();
      const blobUrl = URL.createObjectURL(blob);
      const filename =
        response.headers.get("Content-Disposition")?.match(/filename="(.+)"/)?.[1] ?? "signed.pdf";

      const warningsHeader = response.headers.get("X-Warnings");
      if (warningsHeader) {
        setWarnings(JSON.parse(decodeURIComponent(warningsHeader)));
      }

      setOcspStatus(response.headers.get("X-OCSP-Status") ?? "unknown");
      setTimestamped(response.headers.get("X-Timestamped") === "true");
      setDssAdded(response.headers.get("X-DSS-Added") === "true");
      setSignedPdfUrl(blobUrl);
      setSignedPdfFilename(filename);
      setStage("done");
    } catch (err) {
      setErrorMessage((err as Error).message);
      setStage("error");
    }
  };

  const handleReset = () => {
    if (signedPdfUrl) URL.revokeObjectURL(signedPdfUrl);
    setPdfFile(null);
    setP12File(null);
    setSignatureImageFile(null);
    setPassword("");
    setReason("I have reviewed this document");
    setLocation("Philippines");
    setSignaturePosition(null);
    setStage("idle");
    setWarnings([]);
    setErrorMessage(null);
    setSignedPdfUrl(null);
    setSignedPdfFilename(null);
    setOcspStatus("unknown");
    setTimestamped(false);
    setDssAdded(false);
  };

  return (
    <div className="min-h-svh w-full bg-background">
      {/* Header */}
      <header className="border-b px-6 py-4">
        <div className="mx-auto flex max-w-7xl items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary">
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="white"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div>
            <h1 className="text-sm leading-none font-semibold">PNPKI Document Signer</h1>
            <p className="mt-0.5 text-xs text-muted-foreground">DICT · PAdES-B + OCSP + RFC 3161 TSA</p>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="mx-auto max-w-7xl px-6 py-8">
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-2">
          {/* Left — form panels */}
          <div className="flex flex-col gap-4">
            {/* Step 1 — PDF Upload */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-sm font-medium">
                  <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary text-xs text-primary-foreground">
                    1
                  </span>
                  PDF Document
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div
                  className={cn(
                    "relative flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed p-8 text-center transition-colors",
                    pdfFile
                      ? "border-green-500 bg-green-50 dark:bg-green-950/20"
                      : "border-muted-foreground/25 hover:border-muted-foreground/50"
                  )}
                  onClick={() => document.getElementById("pdf-input")?.click()}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    e.preventDefault();
                    const file = e.dataTransfer.files[0];
                    if (file?.name.toLowerCase().endsWith(".pdf")) {
                      setPdfFile(file);
                    }
                  }}
                >
                  <input
                    id="pdf-input"
                    type="file"
                    accept=".pdf"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) setPdfFile(file);
                    }}
                  />

                  {pdfFile ? (
                    <div className="flex flex-col items-center gap-2">
                      <svg
                        width="32"
                        height="32"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        className="text-green-500"
                      >
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                        <polyline points="14 2 14 8 20 8" />
                      </svg>
                      <p className="text-sm font-medium">{pdfFile.name}</p>
                      <p className="text-xs text-muted-foreground">{(pdfFile.size / 1024).toFixed(1)} KB</p>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="mt-1 h-7 text-xs text-destructive hover:text-destructive"
                        onClick={(e) => {
                          e.stopPropagation();
                          setPdfFile(null);
                          setSignaturePosition(null);
                        }}
                      >
                        Remove
                      </Button>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center gap-2">
                      <svg
                        width="32"
                        height="32"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        className="text-muted-foreground"
                      >
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                        <polyline points="14 2 14 8 20 8" />
                      </svg>
                      <p className="text-sm font-medium">Drop your PDF here</p>
                      <p className="text-xs text-muted-foreground">or click to browse · max 50MB</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Step 2 — Certificate */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-sm font-medium">
                  <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary text-xs text-primary-foreground">
                    2
                  </span>
                  PNPKI Certificate
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                {/* P12 drop zone */}
                <div
                  className={cn(
                    "relative flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed p-6 text-center transition-colors",
                    p12File
                      ? "border-green-500 bg-green-50 dark:bg-green-950/20"
                      : "border-muted-foreground/25 hover:border-muted-foreground/50"
                  )}
                  onClick={() => document.getElementById("p12-input")?.click()}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    e.preventDefault();
                    const file = e.dataTransfer.files[0];
                    if (file?.name.toLowerCase().match(/\.(p12|pfx)$/)) {
                      setP12File(file);
                    }
                  }}
                >
                  <input
                    id="p12-input"
                    type="file"
                    accept=".p12,.pfx"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) setP12File(file);
                    }}
                  />

                  {p12File ? (
                    <div className="flex flex-col items-center gap-2">
                      <svg
                        width="28"
                        height="28"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        className="text-green-500"
                      >
                        <rect x="3" y="11" width="18" height="11" rx="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                      </svg>
                      <p className="text-sm font-medium">{p12File.name}</p>
                      <p className="text-xs text-muted-foreground">{(p12File.size / 1024).toFixed(1)} KB</p>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="mt-1 h-7 text-xs text-destructive hover:text-destructive"
                        onClick={(e) => {
                          e.stopPropagation();
                          setP12File(null);
                        }}
                      >
                        Remove
                      </Button>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center gap-2">
                      <svg
                        width="28"
                        height="28"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        className="text-muted-foreground"
                      >
                        <rect x="3" y="11" width="18" height="11" rx="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                      </svg>
                      <p className="text-sm font-medium">Drop your .p12 certificate here</p>
                      <p className="text-xs text-muted-foreground">
                        or click to browse · downloaded from govca.npki.gov.ph
                      </p>
                    </div>
                  )}
                </div>

                {/* Password */}
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="password">Certificate Password</Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter your P12 password"
                      className="pr-16 font-mono"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute top-1/2 right-1 h-7 -translate-y-1/2 text-xs text-muted-foreground"
                      onClick={() => setShowPassword((v) => !v)}
                      tabIndex={-1}
                    >
                      {showPassword ? "hide" : "show"}
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    The password you set when downloading from the PNPKI self-service portal.
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Step 3 — Signature Details */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-sm font-medium">
                  <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary text-xs text-primary-foreground">
                    3
                  </span>
                  Signature Details
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                {/* Reason */}
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="reason">Reason</Label>
                  <Input
                    id="reason"
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder="e.g. I have reviewed this document"
                  />
                </div>

                {/* Location */}
                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="location">Location</Label>
                  <Input
                    id="location"
                    value={location}
                    onChange={(e) => setLocation(e.target.value)}
                    placeholder="e.g. Manila, Philippines"
                  />
                </div>

                {/* Signature image */}
                <div className="flex flex-col gap-1.5">
                  <Label>
                    Signature Image <span className="text-muted-foreground">(optional)</span>
                  </Label>
                  <div
                    className={cn(
                      "relative flex cursor-pointer items-center gap-4 rounded-lg border-2 border-dashed p-4 transition-colors",
                      signatureImageFile
                        ? "border-green-500 bg-green-50 dark:bg-green-950/20"
                        : "border-muted-foreground/25 hover:border-muted-foreground/50"
                    )}
                    onClick={() => document.getElementById("image-input")?.click()}
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      const file = e.dataTransfer.files[0];
                      if (file && ["image/png", "image/jpeg"].includes(file.type)) {
                        setSignatureImageFile(file);
                      }
                    }}
                  >
                    <input
                      id="image-input"
                      type="file"
                      accept="image/png,image/jpeg"
                      className="hidden"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) setSignatureImageFile(file);
                      }}
                    />

                    {signatureImageFile ? (
                      <>
                        {/* Preview */}
                        <img
                          src={URL.createObjectURL(signatureImageFile)}
                          alt="Signature preview"
                          className="h-14 w-14 rounded border bg-white object-contain"
                        />
                        <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                          <p className="truncate text-sm font-medium">{signatureImageFile.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {(signatureImageFile.size / 1024).toFixed(1)} KB
                          </p>
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 shrink-0 text-xs text-destructive hover:text-destructive"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSignatureImageFile(null);
                          }}
                        >
                          Remove
                        </Button>
                      </>
                    ) : (
                      <div className="flex flex-col gap-1 py-1">
                        <p className="text-sm font-medium">Upload signature image</p>
                        <p className="text-xs text-muted-foreground">
                          PNG or JPG · max 2MB · appears inside the signature stamp
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Warnings */}
            {warnings.length > 0 && (
              <div className="flex flex-col gap-2">
                {warnings.map((w, i) => (
                  <Alert
                    key={i}
                    variant="default"
                    className="border-yellow-500 bg-yellow-50 dark:bg-yellow-950/20"
                  >
                    <AlertDescription className="text-xs text-yellow-700 dark:text-yellow-400">
                      ⚠ {w}
                    </AlertDescription>
                  </Alert>
                ))}
              </div>
            )}

            {/* Error */}
            {stage === "error" && errorMessage && (
              <Alert variant="destructive">
                <AlertDescription className="text-xs">{errorMessage}</AlertDescription>
              </Alert>
            )}

            {/* Sign button */}
            {stage !== "done" && (
              <Button
                className="w-full"
                size="lg"
                disabled={!pdfFile || !p12File || !password || !signaturePosition || stage === "signing"}
                onClick={handleSign}
              >
                {stage === "signing" ? (
                  <span className="flex items-center gap-2">
                    <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                    </svg>
                    Signing document…
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    <svg
                      width="16"
                      height="16"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                    >
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                    Sign Document with PNPKI
                  </span>
                )}
              </Button>
            )}

            {/* Hint when position not set */}
            {!signaturePosition && pdfFile && stage !== "done" && (
              <p className="text-center text-xs text-muted-foreground">
                ← Draw a signature box on the PDF preview to continue
              </p>
            )}

            {/* Result */}
            {stage === "done" && signedPdfUrl && (
              <Card className="border-green-500">
                <CardContent className="flex flex-col gap-4 pt-6">
                  <div className="flex items-center gap-2 text-green-600 dark:text-green-400">
                    <svg
                      width="18"
                      height="18"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2.5"
                    >
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    <span className="text-sm font-semibold">Document Signed Successfully</span>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <Badge variant="secondary">PNPKI</Badge>
                    <Badge variant="outline" className="text-xs">
                      OCSP: {ocspStatus}
                    </Badge>
                    <Badge variant="outline" className="text-xs">
                      {timestamped ? "✓ Timestamped" : "No timestamp"}
                    </Badge>
                    {dssAdded && (
                      <Badge variant="outline" className="text-xs">
                        ✓ PAdES-B-LT
                      </Badge>
                    )}
                  </div>

                  <a href={signedPdfUrl} download={signedPdfFilename ?? "signed.pdf"} className="w-full">
                    <Button className="w-full" variant="outline">
                      <svg
                        width="16"
                        height="16"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        className="mr-2"
                      >
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                        <polyline points="7 10 12 15 17 10" />
                        <line x1="12" y1="15" x2="12" y2="3" />
                      </svg>
                      Download {signedPdfFilename}
                    </Button>
                  </a>

                  <Button variant="ghost" size="sm" className="text-xs" onClick={handleReset}>
                    Sign another document
                  </Button>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Right — PDF preview */}
          <div className="flex flex-col gap-4">
            {pdfFile ? (
              <PdfPreview
                file={pdfFile}
                onPositionDrawn={setSignaturePosition}
                onPageChange={() => setSignaturePosition(null)}
              />
            ) : (
              <div className="flex h-96 items-center justify-center rounded-lg border-2 border-dashed border-muted-foreground/25">
                <p className="text-sm text-muted-foreground">Upload a PDF to preview it here</p>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
