import { AppSidebar } from "@/components/sidebar-nav/AppSidebar";
import { createFileRoute, Outlet } from "@tanstack/react-router";
import { SidebarInset, SidebarProvider } from "@workspace/ui/components/sidebar";

export const Route = createFileRoute("/app/_layout")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <div>
      <SidebarProvider>
        <AppSidebar />
        <SidebarInset>
          <Outlet />
        </SidebarInset>
      </SidebarProvider>
    </div>
  );
}
