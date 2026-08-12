"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { Menu } from "lucide-react";
import { AppSidebar } from "@/components/app-sidebar";
import { BrandLogo } from "@/components/brand-logo";
import { LicenseBanner } from "@/components/license-banner";
import { isAuthed } from "@/lib/auth";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [ready, setReady] = useState(false);
  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => {
    if (!isAuthed()) {
      router.replace("/login");
    } else {
      setReady(true);
    }
  }, [router]);

  // Close the mobile drawer whenever the route changes.
  useEffect(() => {
    setNavOpen(false);
  }, [pathname]);

  if (!ready) return null;

  return (
    // Fixed-height shell: the sidebar stays pinned; only <main> scrolls.
    <div className="flex h-screen overflow-hidden">
      <AppSidebar open={navOpen} onClose={() => setNavOpen(false)} />
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Mobile top bar — the drawer trigger. Hidden once the sidebar is static (lg+). */}
        <header className="flex items-center gap-3 border-b border-border bg-card px-4 py-3 lg:hidden">
          <button
            onClick={() => setNavOpen(true)}
            aria-label="Open navigation"
            className="rounded-md p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <Menu className="h-5 w-5" />
          </button>
          <div className="flex items-center gap-2">
            <BrandLogo className="h-7 w-7" />
            <span className="font-semibold tracking-tight">ExactSurface</span>
          </div>
        </header>
        <main className="min-w-0 flex-1 overflow-x-hidden overflow-y-auto">
          <LicenseBanner />
          <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">{children}</div>
        </main>
      </div>
    </div>
  );
}
