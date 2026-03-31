import { ThemeProvider } from "@/contexts/ThemeProvider";
import { themeScript } from "@/utils/theme-script";
import { HeadContent, Scripts, createRootRoute } from "@tanstack/react-router";
import { TooltipProvider } from "@workspace/ui/components/tooltip";

import appCss from "@workspace/ui/globals.css?url";

export const Route = createRootRoute({
  head: () => ({
    meta: [
      {
        charSet: "utf-8",
      },
      {
        name: "viewport",
        content: "width=device-width, initial-scale=1",
      },
      {
        title: "PaperTrail",
      },
    ],
    links: [
      {
        rel: "stylesheet",
        href: appCss,
      },
    ],
  }),
  shellComponent: RootDocument,
});

function RootDocument({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <HeadContent />
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        <ThemeProvider>
          <TooltipProvider>
            <main className="min-h-svh antialiased">{children}</main>
          </TooltipProvider>
        </ThemeProvider>
        <Scripts />
      </body>
    </html>
  );
}
