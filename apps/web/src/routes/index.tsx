// import { PdfSigner } from "@/components/PdfSigner";
import { ThemeToggle } from "@/components/ThemeToggle";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/")({ component: App });

function App() {
  return (
    <div className="flex min-h-svh items-center justify-center">
      {/* <PdfSigner /> */}
      <ThemeToggle />
    </div>
  );
}
