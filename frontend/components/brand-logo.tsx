import Image from "next/image";

/**
 * The ExactSurface mark. This renders the actual logo asset (`public/logo.png`) rather
 * than a hand-drawn approximation, so the brand is identical everywhere it appears —
 * sidebar, login, browser tab (via `app/icon.png`) and reports.
 */
export function BrandLogo({
  className = "h-7 w-7",
  size = 64,
}: {
  className?: string;
  size?: number;
}) {
  return (
    <Image
      src="/logo.png"
      alt="ExactSurface"
      width={size}
      height={size}
      className={className}
      priority
    />
  );
}
