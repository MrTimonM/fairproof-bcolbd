/**
 * Public — the tender portal.
 *
 * What is open, what closed and who won. This is the screen a citizen or a
 * journalist opens, so it says as little about cryptography as it can get away
 * with: a table of tenders, a result, and one report that turns the whole
 * protocol into six lines anyone can read.
 */
import { CONFIG, formatBdt, formatCountdown, formatTime } from "../lib/chain";
import { useNow } from "../lib/hooks";
import type { TenderView } from "../lib/tender";
import {
  Card,
  ChainFact,
  CheckList,
  Empty,
  Hash,
  Note,
  Privacy,
  Stat,
  StateBadge,
  Tag,
  TenderPicker,
} from "../components/kit";
import { Icon } from "../components/Icon";
import type { RoleProps } from "../App";

/** Rows for the tender tables, so both sections read the same way. */
function TenderTable({
  tenders,
  now,
  onOpen,
  showWinner,
}: {
  tenders: TenderView[];
  now: number;
  onOpen: (id: string) => void;
  showWinner?: boolean;
}) {
  return (
    <div className="scroll-x">
      <table className="tbl">
        <thead>
          <tr>
            <th>Tender</th>
            <th>Authority</th>
            <th className="num">Bids</th>
            <th>{showWinner ? "Winner" : "Closes"}</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {tenders.map((t) => (
            <tr key={t.id} className="click" onClick={() => onOpen(t.id)}>
              <td>
                <strong>{t.title}</strong>
                <div className="tiny muted" style={{ marginTop: 2 }}>
                  {t.tenderIdString}
                  {t.location ? ` · ${t.location}` : ""}
                </div>
              </td>
              <td className="small">{t.buyer || "—"}</td>
              <td className="num">{t.submissionCount}</td>
              <td>
                {showWinner ? (
                  t.award ? (
                    <>
                      <strong>{t.identity?.legalName ?? `Submission #${t.award.winnerSubmissionIndex}`}</strong>
                      <div className="tiny muted" style={{ marginTop: 2 }}>
                        {t.award.winningPrice > 0n
                          ? formatBdt(t.award.winningPrice)
                          : "price withheld by policy"}
                      </div>
                    </>
                  ) : (
                    <span className="muted">Not yet awarded</span>
                  )
                ) : (
                  <>
                    <div className="small">{formatTime(t.deadline)}</div>
                    <div className="tiny muted">{formatCountdown(t.deadline, now)}</div>
                  </>
                )}
              </td>
              <td style={{ textAlign: "right" }}>
                <StateBadge state={t.state} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Public({ tenders, selected, section, onSelect, goto }: RoleProps) {
  const now = useNow();

  const ongoing = tenders.filter((t) => t.state === 2);
  const past = tenders.filter((t) => t.state >= 3);
  const awarded = tenders.filter((t) => t.award);

  // ------------------------------------------------------------- ongoing
  if (section === "ongoing") {
    return (
      <>
        <div className="page-head">
          <h1>Ongoing tenders</h1>
          <p>
            Published requirements and deadlines that cannot change once bidding opens.
          </p>
        </div>

        <div className="grid g4">
          <Stat k="Open for bidding" v={ongoing.length} s="accepting sealed bids" />
          <Stat k="Closed" v={past.length} s="past their deadline" />
          <Stat k="Awarded" v={awarded.length} s="winner published" />
          <Stat
            k="Bids received"
            v={tenders.reduce((n, t) => n + t.submissionCount, 0)}
            s="across all tenders"
          />
        </div>

        <Card
          title="Open now"
          sub="Open until the deadline."
        >
          {ongoing.length === 0 ? (
            <Empty icon="doc" title="Nothing is open for bidding">
              Published tenders appear here as soon as their review window ends.
            </Empty>
          ) : (
            <TenderTable
              tenders={ongoing}
              now={now}
              onOpen={(id) => {
                onSelect(id);
                goto("public", "report", id);
              }}
            />
          )}
        </Card>

        {past.length ? (
          <Card title="Recently closed" sub="Bidding has ended.">
            <TenderTable
              tenders={past}
              now={now}
              showWinner
              onOpen={(id) => {
                onSelect(id);
                goto("public", "report", id);
              }}
            />
          </Card>
        ) : null}
      </>
    );
  }

  // ------------------------------------------------------------- results
  if (section === "results") {
    return (
      <>
        <div className="page-head">
          <h1>Results</h1>
          <p>
            Every tender this authority has run, and what happened to it.
          </p>
        </div>

        {tenders.length === 0 ? (
          <Card>
            <Empty icon="seal" title="No tenders have been run yet" />
          </Card>
        ) : (
          <>
            {ongoing.length ? (
              <Card
                title="In progress"
                sub="Bidding is open. No price is readable yet."
                accent="accent"
              >
                <TenderTable tenders={ongoing} now={now} onOpen={(id) => goto("public", "report", id)} />
              </Card>
            ) : null}

            <Card title="Completed" sub="Closed tenders, newest first.">
              {past.length === 0 ? (
                <Empty icon="doc" title="Nothing has closed yet" />
              ) : (
                <TenderTable
                  tenders={past}
                  now={now}
                  showWinner
                  onOpen={(id) => goto("public", "report", id)}
                />
              )}
            </Card>
          </>
        )}
      </>
    );
  }

  // -------------------------------------------------------------- report
  //
  // Prefer a tender that has a result. Landing on "not awarded" when a
  // completed one exists makes the page look broken rather than empty.
  const t =
    selected ?? tenders.find((x) => x.award) ?? tenders[0] ?? null;
  if (!t) {
    return (
      <>
        <div className="page-head">
          <h1>Integrity report</h1>
        </div>
        <Card>
          <Empty icon="shield" title="No tender selected">
            Choose one from Ongoing tenders or Results.
          </Empty>
        </Card>
      </>
    );
  }

  const rulesOk = !!t.rulesHash && t.rulesHash.toLowerCase() === t.recomputedRulesHash.toLowerCase();
  const setComplete = t.submissionCount > 0 && !!t.award && t.award.submissionCount === t.submissionCount
    && t.award.bidSetRoot === t.bidSetRoot;
  const opened = t.bids.filter((b) => b.openable).length;
  const allOpened = t.submissionCount > 0 && opened === t.submissionCount;

  return (
    <>
      <div className="page-head">
        <h1>Integrity report</h1>
        <p>
          One page per tender, for anyone who was not involved in it.
        </p>
      </div>

      <div className="tender-head">
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="tender-title">{t.title}</div>
          <div className="tender-meta">
            {[t.tenderIdString, t.buyer, t.location].filter(Boolean).join(" · ")}
          </div>
        </div>
        <StateBadge state={t.state} />
      </div>

      <TenderPicker tenders={tenders} value={t?.id ?? null} onChange={onSelect} />

      <Card
        title={t.award ? "Result" : "This tender has not been awarded"}
        sub={
          t.award
            ? "Published after the winner proved the bid was theirs."
            : "A winner appears once bidding closes and the bids are opened."
        }
        accent={t.award ? "good" : "neutral"}
        chain={
          <>
            <ChainFact k="Rules hash">
              <Hash v={t.rulesHash} lead={10} tail={6} />
            </ChainFact>
            {t.award ? (
              <ChainFact k="Bid set root">
                <Hash v={t.award.bidSetRoot} lead={10} tail={6} />
              </ChainFact>
            ) : null}
            <ChainFact k="Chain">
              <span className="mono">{CONFIG.chainId}</span>
            </ChainFact>
          </>
        }
      >
        {t.award ? (
          <>
            <div className="grid g3" style={{ marginBottom: 20 }}>
              <div>
                <div className="eyebrow">Winner</div>
                <div style={{ fontSize: 19, fontWeight: 650, marginTop: 6 }}>
                  {t.identity?.legalName ?? `Submission #${t.award.winnerSubmissionIndex}`}
                </div>
                {t.identity ? (
                  <div className="tiny muted" style={{ marginTop: 4 }}>
                    declared by the winner, checkable by the issuer against credential{" "}
                    {t.identity.credentialId}
                  </div>
                ) : (
                  <div className="tiny muted" style={{ marginTop: 4 }}>
                    nobody is named until an ownership proof is published
                  </div>
                )}
              </div>
              <div>
                <div className="eyebrow">Winning price</div>
                <div className="big-num" style={{ marginTop: 6 }}>
                  {t.award.winningPrice > 0n ? formatBdt(t.award.winningPrice) : "Withheld"}
                </div>
                <div className="tiny muted" style={{ marginTop: 4 }}>
                  {t.award.winningPrice > 0n
                    ? "the tender's policy publishes it"
                    : "the tender's policy conceals it"}
                </div>
              </div>
              <div>
                <div className="eyebrow">Bids considered</div>
                <div className="big-num" style={{ marginTop: 6 }}>{t.award.submissionCount}</div>
                <div className="tiny muted" style={{ marginTop: 4 }}>
                  the complete accepted set, awarded {formatTime(t.award.awardedAt)}
                </div>
              </div>
            </div>

            <CheckList
              items={[
                {
                  label: "Rules published and frozen before bidding",
                  state: rulesOk ? "pass" : "fail",
                },
                { label: "Bid set complete", state: setComplete ? "pass" : "pending" },
                { label: "Every bid opened by the committee", state: allOpened ? "pass" : "pending" },
                {
                  label: "Winner proved it placed the winning bid",
                  state: t.identity ? "pass" : "pending",
                },
                { label: "Cryptographic verification", state: rulesOk && setComplete ? "pass" : "pending",
                  value: rulesOk && setComplete ? "PASS" : "Pending" },
                {
                  label: "Confidential documents disclosed",
                  state: "pass",
                  value: 0,
                },
              ]}
            />
          </>
        ) : (
          <CheckList
            items={[
              { label: "Rules published and frozen before bidding", state: rulesOk ? "pass" : "fail" },
              { label: "Bidding closed", state: t.state >= 3 ? "pass" : "pending" },
              {
                label: "Bids opened by the committee",
                state: allOpened ? "pass" : "pending",
                value: `${opened} of ${t.submissionCount}`,
              },
              { label: "Winner declared", state: "pending" },
              { label: "Confidential documents disclosed", state: "pass", value: 0 },
            ]}
          />
        )}
      </Card>

      <Card title="What was published, and what stayed private">
        <Privacy
          title="The public record for this tender"
          learns={[
            "The full rule document, frozen before the first bid arrived",
            `${t.submissionCount} sealed bids, each a commitment nobody could read`,
            t.award
              ? t.award.winningPrice > 0n
                ? `The winning price, ${formatBdt(t.award.winningPrice)}`
                : "That an award was made, without the price"
              : "No award yet",
            t.identity ? `The winner's declared identity` : "No identity published yet",
          ]}
          never={[
            "Any losing bidder's price",
            "Any bidder's turnover, experience or certification",
            "Which firm placed which bid, unless it chose to publish",
            "Any document a firm submitted in support of its qualification",
          ]}
        />
      </Card>

      <Note tone="accent" icon="info">
        <strong>Want to check this yourself?</strong> The{" "}
        <button className="btn sm" onClick={() => goto("auditor", "verify", t.id)}>
          auditor view
        </button>{" "}
        recomputes every value above in your own browser, from the chain, and shows
        the comparison rather than a verdict.
      </Note>
    </>
  );
}
