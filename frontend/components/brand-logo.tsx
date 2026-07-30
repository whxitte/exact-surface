/**
 * The ExactSurface mark: a scanning reticle — a viewfinder framing a target, with a
 * sweep line meeting the ring where the scan completes. The open segment keeps it
 * reading as "still scanning" rather than a closed, finished circle.
 *
 * Uses `currentColor` throughout so it inherits the surrounding text colour and works
 * on both themes without a second asset.
 */
export function BrandLogo({ className = "h-6 w-6" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label="ExactSurface"
    >
      {/* Outer ring, open at the lower right (4–5 o'clock). */}
      <path
        d="M 76.5 81.6 A 41 41 0 1 1 88.5 63.0"
        stroke="currentColor"
        strokeWidth="7"
        strokeLinecap="round"
      />
      {/* Viewfinder corners. */}
      <path
        d="M 32 41 V 34 A 2 2 0 0 1 34 32 H 41"
        stroke="currentColor"
        strokeWidth="7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M 59 32 H 66 A 2 2 0 0 1 68 34 V 41"
        stroke="currentColor"
        strokeWidth="7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M 32 59 V 66 A 2 2 0 0 0 34 68 H 41"
        stroke="currentColor"
        strokeWidth="7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M 59 68 H 66 A 2 2 0 0 0 68 66 V 59"
        stroke="currentColor"
        strokeWidth="7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Sweep: the locked-on point, and the line running out to the ring. */}
      <line
        x1="46"
        y1="50"
        x2="90"
        y2="50"
        stroke="currentColor"
        strokeWidth="7"
        strokeLinecap="round"
      />
      <circle cx="42" cy="50" r="7.5" fill="currentColor" />
    </svg>
  );
}
