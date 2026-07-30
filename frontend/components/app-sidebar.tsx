"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  LayoutDashboard, Globe, ShieldAlert, Activity, Settings, LogOut, Network,
  GitCompareArrows, BookOpen, X,
} from "lucide-react";
import { BrandLogo } from "@/components/brand-logo";
import { cn } from "@/lib/utils";
import { clearSession } from "@/lib/auth";

const nav = [
  { href: "/overview", label: "Overview", icon: LayoutDashboard },
  { href: "/programs", label: "Programs", icon: Globe },
  { href: "/changes", label: "Changes", icon: GitCompareArrows },
  { href: "/findings", label: "Findings", icon: ShieldAlert },
  { href: "/dns", label: "DNS", icon: Network },
  { href: "/activity", label: "Activity", icon: Activity },
  { href: "/knowledge", label: "Knowledge", icon: BookOpen },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function AppSidebar({ open = false, onClose }: { open?: boolean; onClose?: () => void }) {
  const pathname = usePathname();
  const router = useRouter();

  return (
    <>
      {/* Backdrop — only on mobile, only while the drawer is open. */}
      <div
        onClick={onClose}
        className={cn(
          "fixed inset-0 z-40 bg-black/50 transition-opacity lg:hidden",
          open ? "opacity-100" : "pointer-events-none opacity-0",
        )}
        aria-hidden={!open}
      />

      {/* Static on desktop (lg+); an off-canvas drawer below that. */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex h-screen w-64 max-w-[85vw] shrink-0 flex-col border-r border-border bg-card transition-transform duration-200 lg:static lg:w-60 lg:max-w-none lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex items-center gap-2 px-5 py-5">
          <div className="flex h-8 w-8 items-center justify-center">
            <BrandLogo className="h-8 w-8" />
          </div>
          <div className="leading-tight">
            <div className="font-semibold tracking-tight">ExactSurface</div>
            <div className="text-[10px] uppercase tracking-widest text-muted-foreground">
              attack surface
            </div>
          </div>
          {/* Close button — mobile drawer only. */}
          <button
            onClick={onClose}
            aria-label="Close navigation"
            className="ml-auto rounded-md p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground lg:hidden"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <nav className="flex-1 space-y-1 overflow-y-auto px-3">
          {nav.map(({ href, label, icon: Icon }) => {
            const active = pathname === href || pathname.startsWith(href + "/");
            return (
              <Link
                key={href}
                href={href}
                onClick={onClose}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  active
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
              >
                <Icon className="h-4 w-4 shrink-0" />
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
          <LogOut className="h-4 w-4 shrink-0" />
          Sign out
        </button>
      </aside>
    </>
  );
}
