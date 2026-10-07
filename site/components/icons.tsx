import type { ReactNode, SVGProps } from "react";

/**
 * The page's icons, inlined. A dozen glyphs do not justify an icon package,
 * and an icon font or sprite would be one more request on a page whose whole
 * claim is that you can read its network tab.
 */
type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Stroke({ size = 16, children, ...rest }: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

/** Two arcs making an S. Coloured by the surrounding text colour. */
export function Mark({ size = 22 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2.6}
      strokeLinecap="round"
      aria-hidden="true"
      focusable="false"
      className="mark"
    >
      <path d="M15.03 6.75A3.5 3.5 0 1 0 12 12a3.5 3.5 0 1 1-3.03 5.25" />
    </svg>
  );
}

export function GitHubIcon({ size = 16 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}

export const ArrowDown = (p: IconProps) => (
  <Stroke {...p}>
    <path d="M12 5v14" />
    <path d="m6 13 6 6 6-6" />
  </Stroke>
);

export const ArrowUpRight = (p: IconProps) => (
  <Stroke {...p}>
    <path d="M7 17 17 7" />
    <path d="M8 7h9v9" />
  </Stroke>
);

export const Play = (p: IconProps) => (
  <Stroke {...p}>
    <path d="M7 4.5v15l12-7.5z" />
  </Stroke>
);

/* ── Policies ──────────────────────────────────────────────────────── */

export const TerminalIcon = (p: IconProps) => (
  <Stroke {...p}>
    <path d="m4 7 5 5-5 5" />
    <path d="M12 17h8" />
  </Stroke>
);

export const MessageAlertIcon = (p: IconProps) => (
  <Stroke {...p}>
    <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
    <path d="M12 7v3.5" />
    <path d="M12 13.5h.01" />
  </Stroke>
);

export const TriangleAlertIcon = (p: IconProps) => (
  <Stroke {...p}>
    <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <path d="M12 9v4" />
    <path d="M12 17h.01" />
  </Stroke>
);

export const UserIcon = (p: IconProps) => (
  <Stroke {...p}>
    <circle cx="12" cy="7" r="4" />
    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
  </Stroke>
);

export const KeyIcon = (p: IconProps) => (
  <Stroke {...p}>
    <circle cx="7.5" cy="15.5" r="5.5" />
    <path d="m11.4 11.6 9.6-9.6" />
    <path d="m15.5 7.5 3 3L22 7l-3-3" />
  </Stroke>
);

export const FileTextIcon = (p: IconProps) => (
  <Stroke {...p}>
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <path d="M14 2v6h6" />
    <path d="M16 13H8" />
    <path d="M16 17H8" />
  </Stroke>
);

export const ShieldIcon = (p: IconProps) => (
  <Stroke {...p}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </Stroke>
);

export const BracesIcon = (p: IconProps) => (
  <Stroke {...p}>
    <path d="M8 3H7a2 2 0 0 0-2 2v5a2 2 0 0 1-2 2 2 2 0 0 1 2 2v5a2 2 0 0 0 2 2h1" />
    <path d="M16 21h1a2 2 0 0 0 2-2v-5a2 2 0 0 1 2-2 2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h-1" />
  </Stroke>
);

export const ListIcon = (p: IconProps) => (
  <Stroke {...p}>
    <path d="M8 6h13" />
    <path d="M8 12h13" />
    <path d="M8 18h13" />
    <path d="M3 6h.01" />
    <path d="M3 12h.01" />
    <path d="M3 18h.01" />
  </Stroke>
);

/* ── Decisions ─────────────────────────────────────────────────────── */

export const CheckIcon = (p: IconProps) => (
  <Stroke {...p}>
    <path d="M20 6 9 17l-5-5" />
  </Stroke>
);

/** A line of text with the middle of it blacked out. */
export const RedactIcon = (p: IconProps) => (
  <Stroke {...p}>
    <path d="M4 7h16" />
    <path d="M17 12h3" />
    <rect x="4" y="10.25" width="10" height="3.5" rx="1" fill="currentColor" stroke="none" />
    <path d="M4 17h10" />
  </Stroke>
);

export const SlashIcon = (p: IconProps) => (
  <Stroke {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="m5.64 5.64 12.72 12.72" />
  </Stroke>
);

export const PauseIcon = (p: IconProps) => (
  <Stroke {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M10 15V9" />
    <path d="M14 15V9" />
  </Stroke>
);
