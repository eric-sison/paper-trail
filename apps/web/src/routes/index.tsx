// import { PdfSigner } from "@/components/PdfSigner";
import { ThemeToggle } from "@/components/ThemeToggle";
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/")({ component: App });

function App() {
  return (
    <div className="flex h-full items-center justify-center">
      {/* <PdfSigner /> */}
      <ThemeToggle />
    </div>
  );
}
