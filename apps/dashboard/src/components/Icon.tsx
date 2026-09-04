/**
 * A drawn icon set.
 *
 * The previous interface used unicode glyphs — ◲ ◫ ✎ ◐ ▤ 🛡 ⚠ — which render
 * differently on every platform, sit on the text baseline at unpredictable
 * sizes, and carry an emoji's tone into a procurement record. These are
 * 20×20 line icons on a 1.6px stroke, drawn to the same grid, inheriting
 * `currentColor` so a status colour applies to the mark and its label at once.
 *
 * Every icon here is decorative. Meaning is always carried by an adjacent
 * word — the rule that survives from the first edition — so `aria-hidden` is
 * unconditional and none of them needs a label.
 */
export type IconName =
  | "overview"
  | "authority"
  | "bidder"
  | "committee"
  | "verification"
  | "check"
  | "cross"
  | "dash"
  | "clock"
  | "lock"
  | "shield"
  | "alert"
  | "info"
  | "doc"
  | "anchor"
  | "copy"
  | "chevron"
  | "arrow"
  | "spinner"
  | "dot"
  | "seal";

const P: Record<IconName, JSX.Element> = {
  // A ledger page with rules on it.
  overview: (
    <>
      <rect x="3" y="3" width="14" height="14" rx="1.5" />
      <path d="M3 7.5h14M7.5 7.5V17" />
    </>
  ),
  // A stamp: the authority's act.
  authority: (
    <>
      <path d="M6 8.5a4 4 0 1 1 8 0c0 2-1.5 2.5-1.5 4h-5C7.5 11 6 10.5 6 8.5Z" />
      <path d="M4.5 14.5h11M4 17h12" />
    </>
  ),
  // An envelope, sealed.
  bidder: (
    <>
      <rect x="2.5" y="4.5" width="15" height="11" rx="1.5" />
      <path d="m2.5 6 7.5 5 7.5-5" />
    </>
  ),
  // A key, held in part.
  committee: (
    <>
      <circle cx="7" cy="7" r="3.5" />
      <path d="m9.5 9.5 7 7M14 14l-1.5 1.5M16.5 11.5 15 13" />
    </>
  ),
  // A magnifier over a rule.
  verification: (
    <>
      <circle cx="8.5" cy="8.5" r="5.5" />
      <path d="m12.5 12.5 4.5 4.5M6 8.5h5" />
    </>
  ),
  check: <path d="m4 10.5 4 4 8-9" />,
  cross: <path d="M5 5l10 10M15 5 5 15" />,
  dash: <path d="M4 10h12" />,
  clock: (
    <>
      <circle cx="10" cy="10" r="7.5" />
      <path d="M10 5.5V10l3 2" />
    </>
  ),
  lock: (
    <>
      <rect x="4" y="9" width="12" height="8" rx="1.5" />
      <path d="M6.5 9V6.5a3.5 3.5 0 0 1 7 0V9" />
    </>
  ),
  shield: <path d="M10 2.5 16.5 5v5c0 4-3 6.5-6.5 7.5C6.5 16.5 3.5 14 3.5 10V5L10 2.5Z" />,
  alert: (
    <>
      <path d="M10 3.5 18 16.5H2L10 3.5Z" />
      <path d="M10 8v3.5M10 14h.01" />
    </>
  ),
  info: (
    <>
      <circle cx="10" cy="10" r="7.5" />
      <path d="M10 9v4.5M10 6.5h.01" />
    </>
  ),
  doc: (
    <>
      <path d="M5 2.5h6.5L15 6v11.5H5V2.5Z" />
      <path d="M11 2.5V6h4M7.5 10h5M7.5 13h5" />
    </>
  ),
  anchor: (
    <>
      <circle cx="10" cy="4.5" r="2" />
      <path d="M10 6.5v11M4 11.5a6 6 0 0 0 12 0M6.5 9h7" />
    </>
  ),
  copy: (
    <>
      <rect x="7" y="7" width="10" height="10" rx="1.5" />
      <path d="M13 7V4.5a1.5 1.5 0 0 0-1.5-1.5h-7A1.5 1.5 0 0 0 3 4.5v7A1.5 1.5 0 0 0 4.5 13H7" />
    </>
  ),
  chevron: <path d="m7 5 6 5-6 5" />,
  arrow: <path d="M4 10h12M11.5 5.5 16 10l-4.5 4.5" />,
  spinner: <path d="M10 2.5a7.5 7.5 0 1 0 7.5 7.5" />,
  dot: <circle cx="10" cy="10" r="4" fill="currentColor" stroke="none" />,
  // A wax seal: the bid, closed.
  seal: (
    <>
      <circle cx="10" cy="10" r="6.5" />
      <path d="M10 6.5 11.4 9l2.6.3-2 1.9.6 2.6L10 12.5 7.4 13.8l.6-2.6-2-1.9L8.6 9 10 6.5Z" />
    </>
  ),
};

export function Icon({
  name,
  size = 18,
  className,
  style,
}: {
  name: IconName;
  size?: number;
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      style={{ flex: "0 0 auto", ...style }}
    >
      {P[name]}
    </svg>
  );
}
