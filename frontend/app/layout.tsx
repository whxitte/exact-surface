import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Vantari — Attack Surface Intelligence",
  description: "Continuous external attack-surface intelligence. Detection only.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>{children}</body>
    </html>
  );
}
