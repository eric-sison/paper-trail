import { PdfSigner } from "@/components/PdfSigner";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/")({ component: App });

function App() {
  return (
    <div className="flex min-h-svh bg-background">
      <PdfSigner />
    </div>
  );
}
