import { ChevronRight } from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@workspace/ui/components/collapsible";
import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebar,
} from "@workspace/ui/components/sidebar";
import { Fragment, type FunctionComponent } from "react";
import { useNavigate, useRouterState } from "@tanstack/react-router";
import type { NavItem } from "./_items";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@workspace/ui/components/dropdown-menu";
import { cn } from "@workspace/ui/lib/utils";

type NavMainProps = {
  items: NavItem[];
};

export const NavMain: FunctionComponent<NavMainProps> = ({ items }) => {
  const { open } = useSidebar();

  const navigate = useNavigate();
  const pathname = useRouterState({
    select: (s) => s.location.pathname,
  });

  const setActiveItem = (path: string) => {
    return pathname === path || pathname.startsWith(path + "/app");
  };

  return (
    <SidebarGroup>
      <SidebarGroupLabel className="text-xs font-bold tracking-widest uppercase">General</SidebarGroupLabel>
      <SidebarMenu>
        {items.map((item) => {
          // Check if this item contains sub-items
          if (!item.subItems || item.subItems.length === 0) {
            return (
              <SidebarMenuItem key={item.title}>
                <SidebarMenuButton
                  tooltip={item.title}
                  isActive={setActiveItem(item.url)}
                  onClick={() => {
                    navigate({ to: item.url });
                  }}
                >
                  {item.icon && <item.icon />}
                  <span>{item.title}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            );
          }

          // Check if this item contains sub-items and sidebar is open
          if (item.subItems && open) {
            return (
              <Collapsible
                key={item.title}
                defaultOpen={item.subItems.some((i) => i.url === pathname)}
                className="group/collapsible"
                render={
                  <SidebarMenuItem>
                    <CollapsibleTrigger
                      render={
                        <SidebarMenuButton tooltip={item.title}>
                          {item.icon && <item.icon />}
                          <span>{item.title}</span>
                          <ChevronRight className="ml-auto transition-transform duration-200 group-data-open/collapsible:rotate-90" />
                        </SidebarMenuButton>
                      }
                    />
                    <CollapsibleContent>
                      <SidebarMenuSub>
                        {item.subItems?.map((subItem) => (
                          <SidebarMenuSubItem key={subItem.title}>
                            <SidebarMenuSubButton
                              role="button"
                              isActive={setActiveItem(subItem.url)}
                              onClick={() => {
                                navigate({ to: subItem.url });
                              }}
                            >
                              {subItem.icon && <subItem.icon />}
                              <span>{subItem.title}</span>
                            </SidebarMenuSubButton>
                          </SidebarMenuSubItem>
                        ))}
                      </SidebarMenuSub>
                    </CollapsibleContent>
                  </SidebarMenuItem>
                }
              />
            );
          }

          // Check if this item contains sub-items and sidebar is closed
          if (item.subItems && !open) {
            return (
              <DropdownMenu key={item.title}>
                <SidebarMenuItem>
                  <DropdownMenuTrigger
                    render={
                      <SidebarMenuButton tooltip={item.title}>
                        {item.icon && <item.icon />}
                        <span>{item.title}</span>
                      </SidebarMenuButton>
                    }
                  />
                  <DropdownMenuContent align="start" side="right" className="min-w-52">
                    {item.subItems.map((subItem, index) => {
                      const isLast = index === item.subItems!.length - 1;
                      return (
                        <Fragment key={index}>
                          <DropdownMenuItem
                            key={index}
                            className={cn(setActiveItem(subItem.url) && "bg-secondary")}
                            onClick={() => {
                              navigate({ to: subItem.url });
                            }}
                          >
                            {subItem.icon && <subItem.icon />}
                            <span>{subItem.title}</span>
                          </DropdownMenuItem>

                          {!isLast && <DropdownMenuSeparator />}
                        </Fragment>
                      );
                    })}
                  </DropdownMenuContent>
                </SidebarMenuItem>
              </DropdownMenu>
            );
          }
        })}
      </SidebarMenu>
    </SidebarGroup>
  );
};
