"use client";

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  ShieldAlert,
  Server,
  GitBranch,
  Bell,
  Rss,
  Settings,
  Users,
  ShieldCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";

const items = [
  { href: "/dashboard/overview", label: "Overview", icon: LayoutDashboard },
  { href: "/dashboard/cves", label: "CVE Explorer", icon: ShieldAlert },
  { href: "/dashboard/servers", label: "Servers", icon: Server },
  { href: "/dashboard/correlations", label: "Vulnerabilities", icon: GitBranch },
  { href: "/dashboard/alerts", label: "Alerts", icon: Bell },
  { href: "/dashboard/feeds", label: "Feeds", icon: Rss },
  { href: "/dashboard/users", label: "Users", icon: Users },
  { href: "/dashboard/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  return (
    <aside className="hidden md:flex flex-col w-60 border-r bg-card">
      <div className="px-5 py-5 flex items-center gap-2 border-b">
        <div className="rounded-md bg-primary p-1.5">
          <ShieldCheck className="h-4 w-4 text-primary-foreground" />
        </div>
        <span className="font-semibold tracking-tight">VulnInt</span>
      </div>
      <nav className="flex-1 px-3 py-4 space-y-1">
        {items.map((it) => {
          const active = pathname.startsWith(it.href);
          const Icon = it.icon;
          return (
            <Link
              key={it.href}
              href={it.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                active
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground",
              )}
            >
              <Icon className="h-4 w-4" />
              {it.label}
            </Link>
          );
        })}
      </nav>
      <div className="px-5 py-4 text-xs text-muted-foreground border-t">
        v1.0.0 · internal
      </div>
    </aside>
  );
}
