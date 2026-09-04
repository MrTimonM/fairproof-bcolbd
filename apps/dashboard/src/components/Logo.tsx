/**
 * The FairProof mark.
 *
 * A seal: the impression a procuring authority presses into a record. The
 * ring is the attestation, the keyhole cut through it is what stays private,
 * and the bar across the base is the entry in the register.
 *
 * Drawn in a single ink so it survives a fax, a photocopier and a monochrome
 * projector — which is the actual test for a mark that has to appear on a
 * procurement notice. The previous version was a gradient shield with a glow,
 * which failed all three and looked like every other generated logo.
 */
export function Logo({ size = 28, tone }: { size?: number; tone?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      role="img"
      aria-label="FairProof"
      fill="none"
      stroke={tone ?? "currentColor"}
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {/* the seal */}
      <circle cx="16" cy="14.5" r="10.5" />
      <circle cx="16" cy="14.5" r="7.4" strokeDasharray="1 2.6" />
      {/* the keyhole: what stays private */}
      <circle cx="16" cy="12.6" r="2.5" />
      <path d="M14.6 14.9h2.8l.9 4.2h-4.6l.9-4.2Z" />
      {/* the entry in the register */}
      <path d="M6 28.5h20" strokeWidth="2.2" />
    </svg>
  );
}

/** The mark with the wordmark beside it. */
export function Wordmark({ size = 26 }: { size?: number }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
      <Logo size={size + 4} />
      <span style={{ display: "flex", flexDirection: "column", lineHeight: 1.05 }}>
        <span
          style={{
            fontFamily: "var(--serif)",
            fontSize: size * 0.78,
            letterSpacing: "-0.015em",
          }}
        >
          FairProof
        </span>
        <span
          style={{
            fontSize: size * 0.34,
            fontWeight: 600,
            letterSpacing: "0.11em",
            textTransform: "uppercase",
            color: "var(--ink-3)",
            marginTop: 1,
          }}
        >
          Procurement Register
        </span>
      </span>
    </span>
  );
}
