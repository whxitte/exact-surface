import type { Metadata } from "next";
import "./globals.css";

const DESCRIPTION =
  "Open-source, self-hosted external attack-surface management. Continuously discovers " +
  "your internet-facing assets and shows the exact request behind every finding. " +
  "Detection only.";

// Shared by the product and the demo. The Open Graph image is served from /public so a
// self-hosted instance needs nothing external for a link preview; the demo's absolute
// URLs come from metadataBase, which Next resolves from the deployment host.
export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || "https://exactsurface-demo.vercel.app"),
  title: {
    default: "ExactSurface — Attack Surface Intelligence",
    template: "%s · ExactSurface",
  },
  description: DESCRIPTION,
  applicationName: "ExactSurface",
  openGraph: {
    type: "website",
    siteName: "ExactSurface",
    title: "ExactSurface — Open-source external attack-surface management",
    description: DESCRIPTION,
    images: [{ url: "/og.png", width: 1280, height: 640, alt: "ExactSurface" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "ExactSurface — Open-source external attack-surface management",
    description: DESCRIPTION,
    images: ["/og.png"],
  },
  // A dashboard full of someone's findings must never be indexed, and neither should
  // its login page. The demo is the one deployment that should be found: it builds on
  // Vercel, which sets VERCEL=1 in every build, and nobody deploys a Docker product
  // with a backend to Vercel. NEXT_PUBLIC_INDEXABLE=1 is the explicit override.
  robots:
    process.env.NEXT_PUBLIC_INDEXABLE === "1" || process.env.VERCEL === "1"
      ? "index,follow"
      : "noindex,nofollow",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>{children}</body>
    </html>
  );
}
