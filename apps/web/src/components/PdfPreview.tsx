import { useEffect, useRef, useState } from "react";
import { Button } from "@workspace/ui/components/button";

interface Props {
  file: File;
  onPositionDrawn: (position: {
    page: number;
    screenX: number;
    screenY: number;
    screenWidth: number;
    screenHeight: number;
    pdfX: number;
    pdfY: number;
    pdfWidth: number;
    pdfHeight: number;
  }) => void;
  onPageChange?: () => void;
}

export function PdfPreview({ file, onPositionDrawn, onPageChange }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const overlayRef = useRef<HTMLDivElement>(null);
  const pdfRef = useRef<any>(null);
  const initialLoadDone = useRef(false);

  const [totalPages, setTotalPages] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [pdfPageDimensions, setPdfPageDimensions] = useState<{
    width: number;
    height: number;
  } | null>(null);
  const [drawing, setDrawing] = useState(false);
  const [rect, setRect] = useState<{
    xRatio: number;
    yRatio: number;
    wRatio: number;
    hRatio: number;
  } | null>(null);
  const startPoint = useRef<{ x: number; y: number } | null>(null);

  // ── Effect 1: Load PDF + render page 1 when file changes ────────────────
  useEffect(() => {
    if (!file) return;
    let cancelled = false;

    pdfRef.current = null;
    initialLoadDone.current = false;
    setCurrentPage(1);
    setTotalPages(0);
    setRect(null);

    const run = async () => {
      const pdfjsLib = await import("pdfjs-dist");
      pdfjsLib.GlobalWorkerOptions.workerSrc = new URL(
        "pdfjs-dist/build/pdf.worker.mjs",
        import.meta.url
      ).toString();

      const arrayBuffer = await file.arrayBuffer();
      const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
      if (cancelled) return;

      pdfRef.current = pdf;
      setTotalPages(pdf.numPages);

      if (!canvasRef.current) return;

      const page = await pdf.getPage(1);
      const viewport = page.getViewport({ scale: 1 });
      setPdfPageDimensions({ width: viewport.width, height: viewport.height });

      const canvas = canvasRef.current;
      const containerWidth = canvas.parentElement!.clientWidth;
      const scale = containerWidth / viewport.width;
      const scaledViewport = page.getViewport({ scale });

      canvas.width = scaledViewport.width;
      canvas.height = scaledViewport.height;

      const ctx = canvas.getContext("2d")!;
      const renderContext = {
        canvasContext: ctx,
        canvas: canvas,
        viewport: scaledViewport,
      } as Parameters<typeof page.render>[0];

      await page.render(renderContext).promise;
      if (!cancelled) initialLoadDone.current = true;
    };

    run();
    return () => {
      cancelled = true;
    };
  }, [file]);

  // ── Effect 2: Re-render on page navigation ───────────────────────────────
  useEffect(() => {
    if (!pdfRef.current || !canvasRef.current || !initialLoadDone.current) return;
    let cancelled = false;

    const renderPage = async () => {
      const page = await pdfRef.current.getPage(currentPage);
      const viewport = page.getViewport({ scale: 1 });
      setPdfPageDimensions({ width: viewport.width, height: viewport.height });

      if (!canvasRef.current || cancelled) return;

      const canvas = canvasRef.current;
      const containerWidth = canvas.parentElement!.clientWidth;
      const scale = containerWidth / viewport.width;
      const scaledViewport = page.getViewport({ scale });

      canvas.width = scaledViewport.width;
      canvas.height = scaledViewport.height;

      const ctx = canvas.getContext("2d")!;
      const renderContext = {
        canvasContext: ctx,
        canvas: canvas,
        viewport: scaledViewport,
      } as Parameters<typeof page.render>[0];

      await page.render(renderContext).promise;
      setRect(null);
    };

    renderPage();
    return () => {
      cancelled = true;
    };
  }, [currentPage]);

  // ── Effect 3: Escape key to clear selection ──────────────────────────────
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setRect(null);
        onPageChange?.();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onPageChange]);

  const getRelativePos = (e: React.MouseEvent<HTMLDivElement>) => {
    const overlay = overlayRef.current!;
    const bounds = overlay.getBoundingClientRect();
    return {
      x: e.clientX - bounds.left,
      y: e.clientY - bounds.top,
    };
  };

  const handlePageChange = (newPage: number) => {
    setCurrentPage(newPage);
    setRect(null);
    onPageChange?.();
  };

  const handleMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    const pos = getRelativePos(e);
    const overlay = overlayRef.current!;
    startPoint.current = pos;
    setRect({
      xRatio: pos.x / overlay.clientWidth,
      yRatio: pos.y / overlay.clientHeight,
      wRatio: 0,
      hRatio: 0,
    });
    setDrawing(true);
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!drawing || !startPoint.current) return;
    const pos = getRelativePos(e);
    const overlay = overlayRef.current!;
    const W = overlay.clientWidth;
    const H = overlay.clientHeight;

    const x = Math.min(pos.x, startPoint.current.x);
    const y = Math.min(pos.y, startPoint.current.y);
    const w = Math.abs(pos.x - startPoint.current.x);
    const h = Math.abs(pos.y - startPoint.current.y);

    setRect({
      xRatio: x / W,
      yRatio: y / H,
      wRatio: w / W,
      hRatio: h / H,
    });
  };

  const handleMouseUp = () => {
    if (!drawing || !rect || !pdfPageDimensions || !canvasRef.current) return;
    setDrawing(false);

    const overlay = overlayRef.current!;
    const W = overlay.clientWidth;
    const H = overlay.clientHeight;

    const pw = rect.wRatio * W;
    const ph = rect.hRatio * H;

    // Ignore tiny accidental clicks
    if (pw < 20 || ph < 10) {
      setRect(null);
      return;
    }

    const pdfX = rect.xRatio * pdfPageDimensions.width;
    const pdfY = pdfPageDimensions.height - (rect.yRatio + rect.hRatio) * pdfPageDimensions.height;
    const pdfWidth = rect.wRatio * pdfPageDimensions.width;
    const pdfHeight = rect.hRatio * pdfPageDimensions.height;

    onPositionDrawn({
      page: currentPage,
      screenX: rect.xRatio * W,
      screenY: rect.yRatio * H,
      screenWidth: pw,
      screenHeight: ph,
      pdfX,
      pdfY,
      pdfWidth,
      pdfHeight,
    });
  };

  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs text-muted-foreground">
        {rect && rect.wRatio * (overlayRef.current?.clientWidth ?? 0) > 20
          ? "✓ Signature box placed — drag again to reposition"
          : "Click and drag on the document to place your signature"}
      </p>

      <div className="relative w-full overflow-hidden rounded-lg border bg-muted">
        <canvas ref={canvasRef} className="block w-full" />
        <div
          ref={overlayRef}
          className="absolute inset-0 cursor-crosshair"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          {rect && rect.wRatio > 0 && rect.hRatio > 0 && (
            <div
              className="pointer-events-none absolute border-2 border-primary bg-primary/10"
              style={{
                left: `${rect.xRatio * 100}%`,
                top: `${rect.yRatio * 100}%`,
                width: `${rect.wRatio * 100}%`,
                height: `${rect.hRatio * 100}%`,
              }}
            />
          )}
        </div>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3">
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs"
            disabled={currentPage <= 1}
            onClick={() => handlePageChange(currentPage - 1)}
          >
            ← Prev
          </Button>
          <span className="text-xs text-muted-foreground">
            Page {currentPage} of {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs"
            disabled={currentPage >= totalPages}
            onClick={() => handlePageChange(currentPage + 1)}
          >
            Next →
          </Button>
        </div>
      )}
    </div>
  );
}
