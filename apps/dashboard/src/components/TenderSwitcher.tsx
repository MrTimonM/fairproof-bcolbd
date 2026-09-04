/**
 * The tender switcher in the top bar.
 *
 * The tender under discussion is shared by every role, so changing it is the
 * single most frequent navigation in the product — and a chip that only
 * displayed the current one made that a trip to a sidebar. Clicking it now
 * opens a search box over the list.
 *
 * Filtering matches the title, the reference, the buying authority and the
 * location, because people look a tender up by whichever of those they happen
 * to remember.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import type { TenderView } from "../lib/tender";
import { formatCountdown, formatTime } from "../lib/chain";
import { Icon } from "./Icon";
import { StateBadge } from "./kit";

export function TenderSwitcher({
  tenders,
  selected,
  onSelect,
  now,
}: {
  tenders: TenderView[];
  selected: TenderView | null;
  onSelect: (id: string) => void;
  now: number;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return tenders;
    return tenders.filter((t) =>
      [t.title, t.tenderIdString, t.buyer, t.location]
        .filter(Boolean)
        .some((f) => f.toLowerCase().includes(q)),
    );
  }, [tenders, query]);

  // Reopening should not inherit the last search or a cursor past the end.
  useEffect(() => {
    if (open) {
      setQuery("");
      setCursor(0);
      requestAnimationFrame(() => input.current?.focus());
    }
  }, [open]);

  useEffect(() => {
    setCursor((c) => Math.min(c, Math.max(0, matches.length - 1)));
  }, [matches.length]);

  // Close on a click anywhere else, and on Escape from anywhere.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const choose = (id: string) => {
    onSelect(id);
    setOpen(false);
  };

  if (tenders.length === 0) return null;

  return (
    <div className="switcher" ref={box}>
      <button
        className={`switcher-chip${open ? " on" : ""}`}
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-haspopup="listbox"
        title={selected ? `${selected.title} — ${selected.tenderIdString}` : "Choose a tender"}
      >
        <Icon name="doc" size={15} style={{ color: "var(--ink-4)" }} />
        <b>{selected ? selected.title : "Choose a tender"}</b>
        {selected ? <span className="switcher-ref">{selected.tenderIdString}</span> : null}
        <Icon
          name="chevron"
          size={14}
          style={{ color: "var(--ink-4)", transform: "rotate(90deg)" }}
        />
      </button>

      {open ? (
        <div className="switcher-panel" role="dialog" aria-label="Switch tender">
          <div className="switcher-search">
            <Icon name="verification" size={15} style={{ color: "var(--ink-4)" }} />
            <input
              ref={input}
              value={query}
              placeholder="Search by name, reference, authority or place…"
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  setCursor((c) => Math.min(c + 1, matches.length - 1));
                } else if (e.key === "ArrowUp") {
                  e.preventDefault();
                  setCursor((c) => Math.max(c - 1, 0));
                } else if (e.key === "Enter" && matches[cursor]) {
                  e.preventDefault();
                  choose(matches[cursor].id);
                }
              }}
              aria-label="Search tenders"
            />
            {query ? (
              <button className="switcher-clear" onClick={() => setQuery("")} aria-label="Clear">
                <Icon name="cross" size={13} />
              </button>
            ) : null}
          </div>

          <ul className="switcher-list" role="listbox">
            {matches.length === 0 ? (
              <li className="switcher-none">No tender matches “{query}”.</li>
            ) : (
              matches.map((t, i) => (
                <li key={t.id}>
                  <button
                    role="option"
                    aria-selected={t.id === selected?.id}
                    className={`switcher-item${i === cursor ? " cursor" : ""}${
                      t.id === selected?.id ? " on" : ""
                    }`}
                    onMouseEnter={() => setCursor(i)}
                    onClick={() => choose(t.id)}
                  >
                    <span className="switcher-main">
                      <span className="switcher-title">{t.title}</span>
                      <span className="switcher-meta">
                        {t.tenderIdString}
                        {t.buyer ? ` · ${t.buyer}` : ""}
                        {t.location ? ` · ${t.location}` : ""}
                      </span>
                    </span>
                    <span className="switcher-right">
                      <StateBadge state={t.state} />
                      <span className="switcher-when">
                        {t.submissionCount} bid{t.submissionCount === 1 ? "" : "s"} ·{" "}
                        {t.biddingOpen
                          ? `closes ${formatCountdown(t.deadline, now)}`
                          : formatTime(t.deadline)}
                      </span>
                    </span>
                  </button>
                </li>
              ))
            )}
          </ul>

          <div className="switcher-foot">
            {matches.length} of {tenders.length} · ↑↓ to move, Enter to open, Esc to close
          </div>
        </div>
      ) : null}
    </div>
  );
}
