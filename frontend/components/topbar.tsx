"use client";

import * as React from "react";
import { LogOut, ChevronDown } from "lucide-react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/theme-toggle";
import { auth, logout } from "@/lib/api";

export function Topbar({ title }: { title: string }) {
  const [user, setUser] = React.useState(auth.getUser());
  React.useEffect(() => setUser(auth.getUser()), []);
  const initials = (user?.email || "??")
    .split("@")[0]
    .split(/[._-]/)
    .map((s) => s[0]?.toUpperCase())
    .join("")
    .slice(0, 2);

  return (
    <header className="flex h-14 items-center justify-between border-b bg-card/50 px-5 backdrop-blur supports-[backdrop-filter]:bg-card/40 sticky top-0 z-20">
      <h1 className="text-sm font-semibold tracking-tight">{title}</h1>
      <div className="flex items-center gap-2">
        <ThemeToggle />
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <Button variant="ghost" size="sm" className="gap-2">
              <div className="h-7 w-7 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs font-bold">
                {initials || "?"}
              </div>
              <span className="hidden sm:inline text-sm">{user?.email || "Anonymous"}</span>
              <ChevronDown className="h-3 w-3 opacity-60" />
            </Button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content
              align="end"
              sideOffset={6}
              className="z-50 min-w-[200px] rounded-md border bg-popover p-1 shadow-md"
            >
              <DropdownMenu.Label className="px-2 py-1.5 text-xs text-muted-foreground">
                {user?.full_name || user?.email}
              </DropdownMenu.Label>
              <DropdownMenu.Separator className="my-1 h-px bg-border" />
              <DropdownMenu.Item
                onSelect={logout}
                className="flex cursor-pointer select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none hover:bg-accent"
              >
                <LogOut className="h-4 w-4" />
                Sign out
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    </header>
  );
}
