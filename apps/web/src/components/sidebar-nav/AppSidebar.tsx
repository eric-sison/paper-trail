import * as React from "react";

import { NavMain } from "@/components/sidebar-nav/NavMain";
import { NavUser } from "@/components/sidebar-nav/NavUser";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarRail,
} from "@workspace/ui/components/sidebar";
import { NAVIGATION_ITEMS } from "./_items";

export const AppSidebar: React.FunctionComponent<React.ComponentProps<typeof Sidebar>> = ({ ...props }) => {
  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader>{/* <TeamSwitcher teams={data.teams} /> */}</SidebarHeader>
      <SidebarContent>
        <NavMain items={NAVIGATION_ITEMS.navMain} />
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={NAVIGATION_ITEMS.user} />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
};
