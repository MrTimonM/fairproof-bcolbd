/**
 * The shared component kit.
 *
 * Two rules govern every one of these, and both are about honesty rather than
 * taste:
 *
 *   1. Colour is never the only carrier of meaning. Every status has a drawn
 *      mark AND a word, so it survives a colour-blind reader and a monochrome
 *      projector.
 *   2. Every technical fact gets a plain-language claim AND a route to
 *      verification. "Success" on its own appears nowhere — a claim with no
 *      way to check it is the sort of assertion this protocol exists to
 *      replace.
 */
import { useState, type ReactNode } from "react";
import { ACCOUNTS, TENDER_STATES, roleLabel, shortHash } from "../lib/chain";
import { Icon, type IconName } from "./Icon";

export type Tone = "neutral" | "accent" | "good" | "wait" | "bad";

export function Tag({
  tone = "neutral",
  icon,
  lg,
  children,
}: {
  tone?: Tone;
  icon?: IconName;
  lg?: boolean;
  children: ReactNode;
}) {
  return (
    <span className={`tag ${tone}${lg ? " lg" : ""}`}>
      {icon ? <Icon name={icon} size={lg ? 15 : 13} /> : null}
      {children}
    </span>
  );
}

export function Card({
  title,
  sub,
  right,
  children,
  foot,
  drawer,
  drawerLabel = "How this is verified",
  accent,
  chain,
}: {
  title?: string;
  sub?: string;
  right?: ReactNode;
  children?: ReactNode;
  foot?: ReactNode;
  drawer?: ReactNode;
  drawerLabel?: string;
  accent?: Tone;
  /** Small chain facts, shown quietly at the foot. See `ChainStrip`. */
  chain?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <section className={`card${accent && accent !== "neutral" ? ` tint-${accent}` : ""}`}>
      {title ? (
        <header className="card-head">
          <div style={{ flex: 1, minWidth: 0 }}>
            <h2>{title}</h2>
            {sub ? <div className="card-sub">{sub}</div> : null}
          </div>
          {right}
        </header>
      ) : null}
      {children ? <div className="card-body">{children}</div> : null}
      {chain ? <div className="chain-strip">{chain}</div> : null}
      {foot ? <div className="card-foot">{foot}</div> : null}
      {drawer ? (
        <>
          <button className="drawer-btn" onClick={() => setOpen(!open)} aria-expanded={open}>
            <Icon name="chevron" size={14} />
            {drawerLabel}
          </button>
          {open ? <div className="drawer-body">{drawer}</div> : null}
        </>
      ) : null}
    </section>
  );
}

/** A row of figures, ruled off from one another like a table of results. */
export function Stats({ n = 4, children }: { n?: 3 | 4; children: ReactNode }) {
  return <div className={`stats n${n}`}>{children}</div>;
}

export function Stat({
  k,
  v,
  s,
  tone,
}: {
  k: string;
  v: ReactNode;
  s?: ReactNode;
  tone?: "warn" | "bad";
}) {
  return (
    <div className={`stat${tone ? ` ${tone}` : ""}`}>
      <div className="stat-k">{k}</div>
      <div className="stat-v">{v}</div>
      {s ? <div className="stat-s">{s}</div> : null}
    </div>
  );
}

/**
 * A hash with a copy button and a full-value drawer.
 *
 * Truncation is a display choice, never a data one. A reviewer checking a root
 * against another source needs all 32 bytes, and an ellipsis is useless to
 * them, so the full value is always one click away.
 */
export function Hash({
  v,
  lead = 12,
  tail = 8,
  label,
}: {
  v: string | bigint | null | undefined;
  lead?: number;
  tail?: number;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [open, setOpen] = useState(false);
  if (v === null || v === undefined || v === "") return <span className="muted">—</span>;
  const full = typeof v === "bigint" ? v.toString() : v;

  return (
    <span style={{ display: "inline-block", maxWidth: "100%" }}>
      <span className="hash" title={label}>
        <b>{shortHash(full, lead, tail)}</b>
        <button
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(full);
              setCopied(true);
              setTimeout(() => setCopied(false), 1300);
            } catch {
              setOpen(true);
            }
          }}
          title="Copy the full value"
          aria-label="Copy the full value"
        >
          <Icon name={copied ? "check" : "copy"} size={13} />
        </button>
        <button
          onClick={() => setOpen(!open)}
          title="Show the full value"
          aria-label="Show the full value"
        >
          <Icon name="chevron" size={13} style={open ? { transform: "rotate(90deg)" } : undefined} />
        </button>
      </span>
      {open ? <div className="hash-open">{full}</div> : null}
    </span>
  );
}

export type EvState = "pass" | "fail" | "pending" | "partial";
const EV_ICON: Record<EvState, IconName> = {
  pass: "check",
  fail: "cross",
  pending: "dash",
  partial: "alert",
};
const EV_WORD: Record<EvState, string> = {
  pass: "Verified",
  fail: "Failed",
  pending: "Pending",
  partial: "Partial",
};

export function Evidence({ children }: { children: ReactNode }) {
  return <ul className="ev">{children}</ul>;
}

export function Check({
  state,
  claim,
  detail,
  proof,
}: {
  state: EvState;
  claim: string;
  detail: ReactNode;
  proof?: ReactNode;
}) {
  return (
    <li>
      <span className={`ev-ico ${state}`} title={EV_WORD[state]}>
        <Icon name={EV_ICON[state]} size={18} />
      </span>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div className="ev-claim">
          {claim} <span className="tiny muted">— {EV_WORD[state]}</span>
        </div>
        <div className="ev-detail">{detail}</div>
        {proof ? <div style={{ marginTop: 10 }}>{proof}</div> : null}
      </div>
    </li>
  );
}

export function StateBadge({ state }: { state: number }) {
  const name = TENDER_STATES[state] ?? "Unknown";
  const map: Record<string, { tone: Tone; icon: IconName }> = {
    "Not created": { tone: "neutral", icon: "dash" },
    Draft: { tone: "neutral", icon: "doc" },
    Active: { tone: "accent", icon: "dot" },
    Closed: { tone: "neutral", icon: "lock" },
    Opening: { tone: "wait", icon: "committee" },
    Awarded: { tone: "good", icon: "check" },
    Cancelled: { tone: "bad", icon: "cross" },
  };
  const m = map[name] ?? { tone: "neutral" as Tone, icon: "dash" as IconName };
  return <Tag tone={m.tone} icon={m.icon}>{name}</Tag>;
}

export function Who({ address }: { address: string }) {
  const hit = ACCOUNTS.find((r) => r.address.toLowerCase() === address.toLowerCase());
  return (
    <span className="tag" title={address}>
      {hit ? roleLabel(hit.role) : "Unregistered account"}
    </span>
  );
}

/**
 * A threshold meter showing the count AND the requirement, separately.
 *
 * The whole point of the opening ceremony is that one share and two shares are
 * visibly insufficient. A single "ready" indicator would hide the step that
 * distinguishes a real threshold from a two-party check, so both numbers are
 * always on screen.
 */
export function Threshold({
  count,
  threshold,
  label,
}: {
  count: number;
  threshold: number;
  label?: string;
}) {
  const done = count >= threshold;
  return (
    <div>
      <div className="spread" style={{ marginBottom: 8 }}>
        <span className="small muted">{label ?? "Decryption shares"}</span>
        <span className="row" style={{ gap: 10 }}>
          <strong className="num" style={{ fontSize: 16 }}>
            {count} of {threshold}
          </strong>
          {done ? (
            <Tag tone="good" icon="check">Threshold met</Tag>
          ) : (
            <Tag tone="wait" icon="lock">Still sealed</Tag>
          )}
        </span>
      </div>
      <div className="meter">
        <i
          className={done ? "done" : undefined}
          style={{ width: `${Math.min(100, (count / threshold) * 100)}%` }}
        />
      </div>
    </div>
  );
}

export function Timeline({
  items,
}: {
  items: { title: string; meta?: ReactNode; state: "done" | "active" | "todo" }[];
}) {
  return (
    <ul className="tl">
      {items.map((it, i) => (
        <li key={i}>
          <span className={`tl-dot ${it.state}`}>
            {it.state === "done" ? <Icon name="check" size={12} /> : i + 1}
          </span>
          <div style={{ minWidth: 0 }}>
            <div className="tl-title">{it.title}</div>
            {it.meta ? <div className="tl-meta">{it.meta}</div> : null}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function Privacy({
  learns,
  never,
  title = "What the chain learns, and what it never learns",
}: {
  learns: string[];
  never: string[];
  title?: string;
}) {
  return (
    <div className="privacy">
      <h3>
        <Icon name="shield" size={17} /> {title}
      </h3>
      <div className="privacy-cols">
        <div>
          <h4>Recorded on-chain</h4>
          <ul>{learns.map((l) => <li key={l}>{l}</li>)}</ul>
        </div>
        <div>
          <h4>Never disclosed</h4>
          <ul>{never.map((l) => <li key={l}>{l}</li>)}</ul>
        </div>
      </div>
    </div>
  );
}

export function Note({
  tone = "neutral",
  icon,
  children,
}: {
  tone?: Tone;
  icon?: IconName;
  children: ReactNode;
}) {
  const fallback: IconName =
    tone === "bad" ? "cross" : tone === "wait" ? "alert" : tone === "good" ? "check" : "info";
  return (
    <div className={`note ${tone}`}>
      <span className="note-ico">
        <Icon name={icon ?? fallback} size={17} />
      </span>
      <div style={{ minWidth: 0 }}>{children}</div>
    </div>
  );
}

export function Empty({
  icon = "doc",
  title,
  children,
}: {
  icon?: IconName;
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-ico">
        <Icon name={icon} size={30} />
      </div>
      <h3>{title}</h3>
      {children ? <p>{children}</p> : null}
    </div>
  );
}

/** A failed read, shown as a failed read. Never as an empty panel. */
export function ErrorPanel({
  error,
  hint,
  onRetry,
}: {
  error: string;
  hint?: ReactNode;
  onRetry?: () => void;
}) {
  return (
    <Note tone="bad" icon="cross">
      <strong>Could not read the chain.</strong>
      <div className="small" style={{ marginTop: 5 }}>{error}</div>
      {hint ? <div className="small" style={{ marginTop: 9 }}>{hint}</div> : null}
      {onRetry ? (
        <button className="btn sm" style={{ marginTop: 12 }} onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </Note>
  );
}

export function Loading({ what }: { what: string }) {
  return (
    <div className="empty">
      <div className="empty-ico">
        <span className="spin" style={{ width: 26, height: 26, borderWidth: 2 }} />
      </div>
      <h3>Reading {what}</h3>
      <p>Querying the permissioned chain directly.</p>
    </div>
  );
}

/** A read model that might be behind the chain says so. */
export function Fresh({ at }: { at: number | null }) {
  if (!at) return null;
  const age = Math.round((Date.now() - at) / 1000);
  return age > 20 ? (
    <Tag tone="wait" icon="alert">Stale · {age}s</Tag>
  ) : (
    <Tag tone="neutral" icon="dot">Live</Tag>
  );
}

/** A running transcript of a multi-step operation. */
export type LogLine = { text: string; kind: "ok" | "no" | "wait" | "dim" };

export function Log({ lines }: { lines: LogLine[] }) {
  if (lines.length === 0) return null;
  return (
    <div className="log">
      {lines.map((l, i) => (
        <div key={i} className={l.kind}>
          <span>{l.text}</span>
        </div>
      ))}
    </div>
  );
}

export function Steps({
  steps,
}: {
  steps: { n: string; title: string; detail?: string; state: "todo" | "on" | "ok" | "bad" }[];
}) {
  return (
    <div className="steps">
      {steps.map((s) => (
        <div key={s.n} className={`step${s.state === "todo" ? "" : ` ${s.state}`}`}>
          <span className="step-n">
            {s.state === "ok" ? (
              <Icon name="check" size={13} />
            ) : s.state === "bad" ? (
              <Icon name="cross" size={13} />
            ) : (
              s.n
            )}
          </span>
          <div className="step-body">
            <span className="step-t">{s.title}</span>
            {s.detail ? <span className="step-d">{s.detail}</span> : null}
          </div>
        </div>
      ))}
    </div>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="field">
      <label>{label}</label>
      {children}
      {hint ? <div className="hint">{hint}</div> : null}
    </div>
  );
}

/** The masthead every workspace opens with. */
export function Masthead({
  eyebrow,
  title,
  children,
}: {
  eyebrow: string;
  title: string;
  children?: ReactNode;
}) {
  return (
    <header className="masthead">
      <span className="eyebrow">{eyebrow}</span>
      <h1>{title}</h1>
      {children ? <p>{children}</p> : null}
    </header>
  );
}

/**
 * The tender a workspace is about, named the way a notice names it.
 *
 * The subject leads, because "Construction of a 2 km rural road" is what a
 * reader is looking for and RHD-2026-0147 is what a database is looking for.
 * The reference, the buying authority and the location follow in one line
 * beneath, the way they would under a headline in a gazette.
 */
/**
 * One small chain fact: a label and a value.
 *
 * These live at the foot of a card because almost nobody needs them and the
 * few who do know exactly what they are looking for. Making them the headline
 * would turn a procurement product into a block explorer.
 */
export function ChainFact({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div>
      <span className="k">{k}</span>
      {children}
    </div>
  );
}

/**
 * A tender picker.
 *
 * A row of buttons stops being a picker somewhere around the third tender and
 * becomes a wall. A select stays one control however many there are.
 */
export function TenderPicker({
  tenders,
  value,
  onChange,
  label = "Tender",
}: {
  tenders: { id: string; title: string; tenderIdString: string }[];
  value: string | null;
  onChange: (id: string) => void;
  label?: string;
}) {
  if (tenders.length < 2) return null;
  return (
    <div className="row" style={{ marginBottom: 18, gap: 10 }}>
      <span className="small muted">{label}</span>
      <select
        className="in"
        style={{ maxWidth: 460 }}
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
      >
        {tenders.map((t) => (
          <option key={t.id} value={t.id}>
            {t.title} — {t.tenderIdString}
          </option>
        ))}
      </select>
    </div>
  );
}

/** A row of checks, set large, for the integrity report. */
export function CheckList({
  items,
}: {
  items: { label: string; state: "pass" | "pending" | "fail"; value?: ReactNode }[];
}) {
  return (
    <div className="checks">
      {items.map((it) => (
        <div key={it.label}>
          <span className={`mark ${it.state}`}>
            <Icon
              name={it.state === "pass" ? "check" : it.state === "fail" ? "cross" : "dash"}
              size={14}
            />
          </span>
          {it.label}
          {it.value !== undefined ? (
            <span className={`v${it.state === "pass" ? " pass" : ""}`}>{it.value}</span>
          ) : (
            <span className={`v${it.state === "pass" ? " pass" : ""}`}>
              {it.state === "pass" ? "Verified" : it.state === "fail" ? "Failed" : "Pending"}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

export function TenderHead({
  title,
  reference,
  buyer,
  location,
  right,
}: {
  title: string;
  reference: string;
  buyer?: string;
  location?: string;
  right?: ReactNode;
}) {
  const line = [reference, buyer, location].filter(Boolean).join(" · ");
  return (
    <div className="tender-head">
      <div style={{ flex: 1, minWidth: 0 }}>
        <h2 className="tender-title">{title}</h2>
        <div className="tender-meta">{line}</div>
      </div>
      {right}
    </div>
  );
}

/** Kept as an alias so status wording stays consistent where `Pill` was used. */
export { Tag as Pill };
