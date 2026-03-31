import {
  AppWindowMacIcon,
  AudioWaveform,
  Command,
  FileChartLineIcon,
  FolderArchiveIcon,
  GalleryVerticalEnd,
  NetworkIcon,
  SettingsIcon,
  Users,
  type LucideIcon,
} from "lucide-react";

export type NavItem = {
  title: string;
  url: string;
  icon?: LucideIcon;
  subItems?: NavSubItem[];
};

export type NavSubItem = Pick<NavItem, "title" | "url">;

export const NAVIGATION_ITEMS = {
  user: {
    name: "shadcn",
    email: "m@example.com",
    avatar: "/avatars/shadcn.jpg",
  },

  teams: [
    {
      name: "Acme Inc",
      logo: GalleryVerticalEnd,
      plan: "Enterprise",
    },
    {
      name: "Acme Corp.",
      logo: AudioWaveform,
      plan: "Startup",
    },
    {
      name: "Evil Corp.",
      logo: Command,
      plan: "Free",
    },
  ],

  navMain: [
    {
      title: "Dashboard",
      url: "/app",
      icon: AppWindowMacIcon,
      subItems: [
        {
          title: "Overview",
          url: "/app/overview",
        },
        {
          title: "Recent Activities",
          url: "/app/recent-activities",
        },
      ],
    },
    {
      title: "Documents",
      url: "/app/documents",
      icon: FolderArchiveIcon,
      subItems: [
        {
          title: "All Documents",
          url: "/app/documents/all",
        },
        {
          title: "Drafts",
          url: "/app/documents/drafts",
        },
        {
          title: "In Review",
          url: "/app/documents/in-review",
        },
        {
          title: "Rejected",
          url: "/app/documents/rejected",
        },
        {
          title: "Archived",
          url: "/app/documents/archived",
        },
      ],
    },
    {
      title: "Workflow",
      url: "/app/workflow",
      icon: NetworkIcon,
      subItems: [
        {
          title: "Submissions",
          url: "/app/workflow/submission",
        },
        {
          title: "Approvals Queue",
          url: "/app/workflow/approvals-queue",
        },
        {
          title: "Review Assignments",
          url: "/app/workflow/review-assignments",
        },
        {
          title: "Audit Trail",
          url: "audit-trail",
        },
      ],
    },
    {
      title: "Reports",
      url: "/app/reports",
      icon: FileChartLineIcon,
    },
    {
      title: "Users",
      url: "/app/users",
      icon: Users,
    },
    {
      title: "Settings",
      url: "/app/settings",
      icon: SettingsIcon,
      subItems: [
        {
          title: "General Settings",
          url: "/app/settings/general",
        },
        {
          title: "Workflow configuration",
          url: "/app/settings/workflow-configuration",
        },
        {
          title: "Storage Settings",
          url: "/app/settings/storage",
        },
        {
          title: "Security",
          url: "/app/settings/security",
        },
        {
          title: "Audit Settings",
          url: "/app/settings/audit",
        },
      ],
    },
  ] as NavItem[],
} as const;
