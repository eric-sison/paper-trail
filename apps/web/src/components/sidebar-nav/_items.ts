import {
  AppWindowMacIcon,
  AudioWaveform,
  Command,
  Database,
  FileArchive,
  FileChartLineIcon,
  FileSearchCorner,
  FileStack,
  FileSymlink,
  FileXCorner,
  FolderArchiveIcon,
  Forward,
  GalleryVerticalEnd,
  GitCompareArrows,
  History,
  ListTodo,
  NetworkIcon,
  PanelsTopLeft,
  PencilLine,
  SettingsIcon,
  UserCog,
  UserPen,
  Users,
  ShieldCogCorner,
  type LucideIcon,
  FileCog,
} from "lucide-react";

export type NavItem = {
  title: string;
  url: string;
  icon?: LucideIcon;
  subItems?: NavSubItem[];
};

export type NavSubItem = Pick<NavItem, "title" | "url" | "icon">;

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
          icon: PanelsTopLeft,
        },
        {
          title: "Recent Activities",
          url: "/app/recent-activities",
          icon: History,
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
          icon: FileStack,
        },
        {
          title: "Drafts",
          url: "/app/documents/drafts",
          icon: FileSymlink,
        },
        {
          title: "In Review",
          url: "/app/documents/in-review",
          icon: FileSearchCorner,
        },
        {
          title: "Rejected",
          url: "/app/documents/rejected",
          icon: FileXCorner,
        },
        {
          title: "Archived",
          url: "/app/documents/archived",
          icon: FileArchive,
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
          icon: Forward,
        },
        {
          title: "Approvals Queue",
          url: "/app/workflow/approvals-queue",
          icon: ListTodo,
        },
        {
          title: "Review Assignments",
          url: "/app/workflow/review-assignments",
          icon: UserPen,
        },
        {
          title: "Audit Trail",
          url: "audit-trail",
          icon: PencilLine,
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
          icon: UserCog,
        },
        {
          title: "Workflow configuration",
          url: "/app/settings/workflow-configuration",
          icon: GitCompareArrows,
        },
        {
          title: "Storage Settings",
          url: "/app/settings/storage",
          icon: Database,
        },
        {
          title: "Security",
          url: "/app/settings/security",
          icon: ShieldCogCorner,
        },
        {
          title: "Audit Settings",
          url: "/app/settings/audit",
          icon: FileCog,
        },
      ],
    },
  ] as NavItem[],
} as const;
