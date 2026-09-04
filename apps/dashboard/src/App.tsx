/**
 * The application shell.
 *
 * Four audiences, and they want different things. The public wants to know
 * what is open and who won. A firm wants to know whether it qualifies and what
 * happened to its bid. A procuring authority wants to run a procurement. An
 * auditor wants to check the cryptography. Putting all four in one view is
 * what made the first version of this unreadable.
 *
 * So: the top bar switches role, the sidebar lists that role's sections, and
 * the tender under discussion is shared across all of them — because the story
 * only works if the tender the authority publishes is the one the firm bids on
 * and the public later reads the result of.
 */
import { useEffect, useMemo, useState } from "react";
import { CONFIG, providers } from "./lib/chain";
import { useNow, usePoll } from "./lib/hooks";
import { readTender, readTenderIds, type TenderView } from "./lib/tender";
import { Logo } from "./components/Logo";
import { ErrorPanel, Loading, Tag } from "./components/kit";
import { TenderSwitcher } from "./components/TenderSwitcher";
import { Icon, type IconName } from "./components/Icon";
import Public from "./pages/Public";
import Bidder from "./pages/Bidder";
import Authority from "./pages/Authority";
import Auditor from "./pages/Auditor";
import Certifier from "./pages/Certifier";

export type RoleId = "public" | "bidder" | "certifier" | "authority" | "auditor";

export interface Section {
  id: string;
  label: string;
  icon: IconName;
}

export interface Role {
  id: RoleId;
  label: string;
  icon: IconName;
  /** Who the reader is standing in for. Shown beside the role switcher. */
  actor: string;
  sections: Section[];
}

export const ROLES: Role[] = [
  {
    id: "public",
    label: "Public",
    icon: "overview",
    actor: "Anyone",
    sections: [
      { id: "ongoing", label: "Ongoing tenders", icon: "doc" },
      { id: "results", label: "Results", icon: "seal" },
      { id: "report", label: "Integrity report", icon: "shield" },
    ],
  },
  {
    id: "bidder",
    label: "Bidder",
    icon: "bidder",
    actor: "A bidding firm",
    sections: [
      { id: "available", label: "Available tenders", icon: "doc" },
      { id: "credentials", label: "My company", icon: "seal" },
      { id: "submit", label: "Submit bid", icon: "bidder" },
      { id: "mybids", label: "My bids", icon: "verification" },
    ],
  },
  {
    id: "certifier",
    label: "Certifying body",
    icon: "seal",
    actor: "An accredited certifying body",
    sections: [
      { id: "issue", label: "Issue a credential", icon: "seal" },
      { id: "accreditation", label: "This body", icon: "shield" },
    ],
  },
  {
    id: "authority",
    label: "Authority",
    icon: "authority",
    actor: "The procuring authority",
    sections: [
      { id: "create", label: "Create tender", icon: "authority" },
      { id: "manage", label: "All tenders", icon: "doc" },
      { id: "opening", label: "Bid opening", icon: "committee" },
      { id: "award", label: "Award", icon: "seal" },
    ],
  },
  {
    id: "auditor",
    label: "Auditor",
    icon: "verification",
    actor: "An independent auditor",
    sections: [{ id: "verify", label: "Verification", icon: "verification" }],
  },
];

/** Live QBFT health, read from every validator independently. */
function NetworkStatus() {
  const { data } = usePoll(async () => {
    const results = await Promise.all(
      providers.map(async (p) => {
        try {
          return await p.getBlockNumber();
        } catch {
          return null;
        }
      }),
    );
    return {
      up: results.filter((r) => r !== null).length,
      head: Math.max(0, ...results.map((r) => r ?? 0)),
    };
  }, 4000);

  if (!data) return <Tag icon="dash">Connecting</Tag>;

  const total = CONFIG.validators.length;
  const tolerated = Math.floor((total - 1) / 3);
  const down = total - data.up;
  const tone = down === 0 ? "good" : down <= tolerated ? "wait" : "bad";
  const word = down === 0 ? "Network healthy" : down <= tolerated ? "Degraded" : "Halted";

  return (
    <span className="row" style={{ gap: 9 }}>
      <Tag tone={tone} icon={down === 0 ? "dot" : "alert"}>
        {word}
      </Tag>
      <span className="tiny muted nowrap num">
        {data.up}/{total} validators · block {data.head.toLocaleString()}
      </span>
    </span>
  );
}

export default function App() {
  const now = useNow();
  const [roleId, setRoleId] = useState<RoleId>("public");
  const [sectionId, setSectionId] = useState<string>("ongoing");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  /**
   * Every tender, once, for the whole app.
   *
   * A section that fetched its own copy would show a different state in the
   * sidebar than in the panel beside it whenever a transaction landed between
   * the two calls.
   */
  const tenders = usePoll<TenderView[]>(async () => {
    const ids = await readTenderIds();
    return Promise.all(ids.map(readTender));
  }, 5000);

  const list = tenders.data ?? [];
  const selected = useMemo(
    () => list.find((t) => t.id === selectedId) ?? list[0] ?? null,
    [list, selectedId],
  );

  const role = ROLES.find((r) => r.id === roleId)!;
  const section = role.sections.find((s) => s.id === sectionId) ?? role.sections[0];

  // Switching role lands on that role's first section rather than a stale one.
  useEffect(() => {
    if (!role.sections.some((s) => s.id === sectionId)) setSectionId(role.sections[0].id);
  }, [roleId]);

  const firstLoad = tenders.loading && !tenders.data;

  const shared = {
    tenders: list,
    selected,
    section: section.id,
    onSelect: (id: string) => setSelectedId(id),
    refresh: tenders.refresh,
    goto: (r: RoleId, s?: string, tenderId?: string) => {
      if (tenderId) setSelectedId(tenderId);
      setRoleId(r);
      if (s) setSectionId(s);
      window.scrollTo({ top: 0, behavior: "smooth" });
    },
  };

  /** A count worth showing beside a section name, or nothing. */
  const badgeFor = (id: string): number | null => {
    if (!selected) return null;
    if (id === "results") return list.filter((t) => t.award).length || null;
    if (id === "ongoing" || id === "available") return list.filter((t) => t.state === 2).length || null;
    if (id === "mybids" || id === "opening") return selected.submissionCount || null;
    return null;
  };

  return (
    <div className="shell">
      <header className="topbar">
        <span className="row" style={{ gap: 9 }}>
          <Logo size={26} />
          <strong style={{ fontSize: 16.5, letterSpacing: "-0.02em" }}>FairProof</strong>
        </span>

        <TenderSwitcher
          tenders={list}
          selected={selected}
          onSelect={setSelectedId}
          now={now}
        />

        <div className="topbar-spacer" />

        <div className="roles" role="tablist" aria-label="Role">
          {ROLES.map((r) => (
            <button
              key={r.id}
              role="tab"
              aria-selected={roleId === r.id}
              className={`role-tab${roleId === r.id ? " on" : ""}`}
              onClick={() => setRoleId(r.id)}
              title={`View as ${r.actor}`}
            >
              <Icon name={r.icon} size={15} /> {r.label}
            </button>
          ))}
        </div>

        <div className="topbar-spacer" />
        <NetworkStatus />
      </header>

      <nav className="nav" aria-label={`${role.label} sections`}>
        <div className="nav-label eyebrow">{role.actor}</div>
        {role.sections.map((s) => {
          const badge = badgeFor(s.id);
          return (
            <button
              key={s.id}
              className={`nav-item${section.id === s.id ? " on" : ""}`}
              onClick={() => setSectionId(s.id)}
              aria-current={section.id === s.id ? "page" : undefined}
            >
              <span className="nav-ico">
                <Icon name={s.icon} size={16} />
              </span>
              {s.label}
              {badge ? <span className="nav-badge">{badge}</span> : null}
            </button>
          );
        })}
      </nav>

      <main className="main">
        {tenders.error && !tenders.data ? (
          <ErrorPanel
            error={tenders.error}
            hint={
              <>
                This reads the validators directly. Check the network is up with{" "}
                <code>npm run network:health</code>, then try again.
              </>
            }
            onRetry={tenders.refresh}
          />
        ) : firstLoad ? (
          <Loading what="tenders" />
        ) : roleId === "public" ? (
          <Public {...shared} />
        ) : roleId === "bidder" ? (
          <Bidder {...shared} />
        ) : roleId === "certifier" ? (
          <Certifier {...shared} />
        ) : roleId === "authority" ? (
          <Authority {...shared} />
        ) : (
          <Auditor {...shared} />
        )}
      </main>
    </div>
  );
}

/** What every role page receives. */
export interface RoleProps {
  tenders: TenderView[];
  selected: TenderView | null;
  /** Which of this role's sections is open. */
  section: string;
  onSelect: (id: string) => void;
  refresh: () => void;
  goto: (role: RoleId, section?: string, tenderId?: string) => void;
}
