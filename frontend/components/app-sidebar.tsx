"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  LayoutDashboard, Globe, ShieldAlert, Activity, Settings, LogOut, Radar, Network,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { clearSession } from "@/lib/auth";

const nav = [
  { href: "/overview", label: "Overview", icon: LayoutDashboard },
  { href: "/programs", label: "Programs", icon: Globe },
  { href: "/findings", label: "Findings", icon: ShieldAlert },
  { href: "/dns", label: "DNS", icon: Network },
  { href: "/activity", label: "Activity", icon: Activity },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function AppSidebar() {
  const pathname = usePathname();
  const router = useRouter();

  return (
    <aside className="flex h-screen w-60 shrink-0 flex-col border-r border-border bg-card">
      <div className="flex items-center gap-2 px-5 py-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/15 text-primary">
          <Radar className="h-5 w-5" />
        </div>
        <div className="leading-tight">
          <div className="font-semibold tracking-tight">Vantari</div>
          <div className="text-[10px] uppercase tracking-widest text-muted-foreground">
            attack surface
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3">
        {nav.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + "/");
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                active
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground",
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </Link>
          );
        })}
      </nav>

      <button
        onClick={() => {
          clearSession();
          router.push("/login");
        }}
        className="m-3 flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
      >
        <LogOut className="h-4 w-4" />
        Sign out
      </button>
    </aside>
  );
}
