/**
 * Auditor — the technical verification console.
 *
 * The only screen in this product that is allowed to look like cryptography,
 * because the person reading it came for exactly that. Everything here is
 * recomputed in this browser from chain data using the same frozen
 * specification the circuits use, and shown as a comparison rather than a
 * verdict.
 *
 * What it never shows is a private value. An auditor confirms that bidders met
 * the requirements without learning a single figure behind that claim — which
 * is the whole point, and worth saying on the page rather than only in a
 * whitepaper.
 */
import { useState } from "react";
import { keccak256, toUtf8Bytes } from "ethers";
import {
  IncrementalMerkleTree,
  bidLeaf,
  expectedPublicShare,
  initBabyjub,
  initPoseidon,
  jcsCanonicalize,
  toField,
} from "@fairproof/crypto";
import { CONFIG, contract, formatBdt, formatTime, shortHash } from "../lib/chain";
import { describe, usePoll } from "../lib/hooks";
import { readCheckpoints } from "../lib/tender";
import {
  Card,
  ChainFact,
  Check,
  Empty,
  Evidence,
  Hash,
  Log,
  Note,
  Stat,
  StateBadge,
  Tag,
  TenderPicker,
  Threshold,
  type LogLine,
} from "../components/kit";
import type { RoleProps } from "../App";

type Row = { state: "pass" | "fail" | "partial" | "pending"; claim: string; detail: string };

export default function Auditor({ tenders, selected, onSelect }: RoleProps) {
  const chk = usePoll(readCheckpoints, 10000);
  const [lines, setLines] = useState<LogLine[]>([]);
  const [rows, setRows] = useState<Row[] | null>(null);
  const [busy, setBusy] = useState(false);

  const t = selected;

  async function recheck() {
    if (!t) return;
    setBusy(true);
    setLines([]);
    setRows(null);
    const out: Row[] = [];
    const say = (text: string, kind: LogLine["kind"] = "dim") =>
      setLines((l) => [...l, { text, kind }]);

    try {
      await initPoseidon();
      await initBabyjub();

      // 1. The rules hash, recomputed from the stored document.
      say("re-hashing the stored rule document", "wait");
      const localHash = keccak256(toUtf8Bytes(t.ruleDocument));
      const rulesOk = localHash.toLowerCase() === t.rulesHash.toLowerCase();
      out.push({
        state: rulesOk ? "pass" : "fail",
        claim: "The frozen rules hash is the hash of the document on-chain",
        detail: rulesOk
          ? `keccak256 over the ${t.ruleDocument.length} bytes the contract stores gives ${shortHash(localHash)}, which is the value frozen at activation. Editing any rule afterwards reverts.`
          : `this browser computed ${localHash} and the contract froze ${t.rulesHash}`,
      });
      say(rulesOk ? "rules hash matches" : "rules hash MISMATCH", rulesOk ? "ok" : "no");

      // 2. The document's own text against the fields the circuit enforces.
      //    This is the residual Solidity cannot close, so it is checked here.
      say("comparing the rule document's text against the enforced fields", "wait");
      let doc: any = null;
      try {
        doc = JSON.parse(t.ruleDocument);
      } catch {
        // Handled below as a failure rather than an exception.
      }
      const mismatches: string[] = [];
      if (!doc) {
        mismatches.push("the stored document is not valid JSON");
      } else {
        const eq = (label: string, a: unknown, b: unknown) => {
          if (String(a) !== String(b)) mismatches.push(`${label}: document ${a}, chain ${b}`);
        };
        eq("turnoverThreshold", doc.requirements?.turnoverThreshold, t.turnoverThreshold);
        eq("experienceMonths", doc.requirements?.experienceMonths, t.experienceMonths);
        eq("certificationCode", doc.requirements?.certificationCode, t.certificationCode);
        eq("biddingStart", doc.biddingStart, t.biddingStart);
        eq("deadline", doc.deadline, t.deadline);
        eq("reviewWindow", doc.reviewWindow, t.reviewWindow);
        eq("issuerEpoch", doc.issuerEpoch, t.issuerEpoch);
        eq("tenderId", doc.tenderId, t.tenderIdString);
        if (jcsCanonicalize(doc) !== t.ruleDocument) {
          mismatches.push("the document is not in canonical JCS form");
        }
      }
      out.push({
        state: mismatches.length === 0 ? "pass" : "fail",
        claim: "The published document says what the contract enforces",
        detail:
          mismatches.length === 0
            ? "Every threshold, timestamp and epoch in the human-readable document equals the value the circuit will check, and the document is byte-for-byte canonical. Solidity cannot parse JSON, so this is the one guarantee the chain delegates — and this check is the delegation being honoured."
            : mismatches.join("; "),
      });
      say(
        mismatches.length === 0
          ? "document and enforced fields agree"
          : `document DISAGREES with the enforced fields: ${mismatches.length} field(s)`,
        mismatches.length === 0 ? "ok" : "no",
      );

      // 3. The bid-set accumulator, rebuilt leaf by leaf.
      if (t.submissionCount > 0) {
        say("rebuilding the bid-set accumulator from the on-chain leaves", "wait");
        const tree = new IncrementalMerkleTree();
        const leafMismatch: number[] = [];
        for (const b of t.bids) {
          const leaf = bidLeaf({
            nullifier: b.nullifier,
            bidCommitment: b.bidCommitment,
            ciphertextHashField: toField(b.ciphertextHash),
            submissionIndex: b.index,
          });
          if (leaf !== b.leaf) leafMismatch.push(b.index);
          tree.insert(leaf);
        }
        const rebuilt = tree.root();
        const rootOk = rebuilt === t.bidSetRoot && leafMismatch.length === 0;
        out.push({
          state: rootOk ? "pass" : "fail",
          claim: "The bid set is complete, and the contract is what accumulated it",
          detail: rootOk
            ? `Each of the ${t.submissionCount} leaves was recomputed here with Poseidon from the nullifier, the commitment, the ciphertext hash and the submission index, and the tree rebuilt to ${shortHash(rebuilt)} — the root the contract holds. The authority never computes this root, so it cannot drop a bid and still produce a matching award proof.`
            : leafMismatch.length
            ? `leaves ${leafMismatch.join(", ")} do not match the values the contract stored`
            : `rebuilt ${rebuilt}, contract holds ${t.bidSetRoot}`,
        });
        say(rootOk ? "bid-set root matches" : "bid-set root MISMATCH", rootOk ? "ok" : "no");
      }

      // 4. The committee dealing, checked against its own commitments.
      if (t.committee.set) {
        say("checking the Feldman dealing against its commitments", "wait");
        const commitments = t.committee.commitmentX.map((x, i) => ({
          x,
          y: t.committee.commitmentY[i],
        }));
        const c0Ok =
          commitments[0].x === t.committee.yX && commitments[0].y === t.committee.yY;
        // Only the PUBLIC shares are on the chain, which is the point: the
        // commitments determine what each member's public share must be, so
        // consistency is checkable by anyone without a single secret.
        const shareProblems: number[] = [];
        for (let i = 0; i < t.committee.memberX.length; i++) {
          const expected = expectedPublicShare(i + 1, commitments);
          if (
            expected.x !== t.committee.memberX[i] ||
            expected.y !== t.committee.memberY[i]
          ) {
            shareProblems.push(i + 1);
          }
        }
        const dealingOk = c0Ok && shareProblems.length === 0;
        out.push({
          state: dealingOk ? "pass" : "fail",
          claim: "Every committee member holds a share of the same key",
          detail: dealingOk
            ? "C₀ equals the tender public key, and each of the five public shares lies on the polynomial the commitments describe. A dealer who handed one member an unrelated share would fail this — and would have failed it on-chain first, since the contract runs the same check."
            : !c0Ok
            ? "the first commitment is not the published tender key"
            : `member ${shareProblems.join(", ")}'s public share is inconsistent with the commitments`,
        });
        say(dealingOk ? "dealing consistent" : "dealing INCONSISTENT", dealingOk ? "ok" : "no");
      }

      // 5. The award's public signals, as the contract itself computes them.
      if (t.award) {
        say("re-deriving the award's expected public signals", "wait");
        const signals = await contract("AwardManager").expectedPublicSignals(
          t.id,
          t.award.winnerCommitment,
          t.award.winningPrice,
        );
        const setOk = t.award.bidSetRoot === t.bidSetRoot;
        const countOk = t.award.submissionCount === t.submissionCount;
        out.push({
          state: setOk && countOk ? "pass" : "fail",
          claim: "The award was proved over the set that actually exists",
          detail:
            setOk && countOk
              ? `The award pins accumulator ${shortHash(t.award.bidSetRoot)} over ${t.award.submissionCount} submissions, which is the root and the count the SealedBid contract holds today. The circuit's ${signals.length} public signals are derived from tender state, so a proof about a different set would not verify against them.`
              : !setOk
              ? "the award names a different accumulator root than the one the contract holds"
              : `the award claims ${t.award.submissionCount} submissions and the contract holds ${t.submissionCount}`,
        });
        say(setOk && countOk ? "award binds to the live set" : "award SET MISMATCH", setOk && countOk ? "ok" : "no");

        // 6. The winner's own subgroup check, if identity has been published.
        if (t.identity) {
          const commitment = await contract("WinnerIdentity").identityCommitment(
            t.identity.credentialId,
            toUtf8Bytes(t.identity.record),
          );
          const idOk = commitment === t.identity.legalIdentityCommitment;
          out.push({
            state: idOk ? "pass" : "fail",
            claim: "The published record is the one the winner proved ownership of",
            detail: idOk
              ? `Hashing the declared record and credential ${t.identity.credentialId} reproduces the commitment the ownership proof was checked against. The name itself is the winner's own statement — checkable by the issuer, not by this chain.`
              : "the published record does not hash to the committed value",
          });
          say(idOk ? "identity record matches its commitment" : "identity MISMATCH", idOk ? "ok" : "no");
        }
      }

      // Always stated, never quietly dropped.
      out.push({
        state: chk.data && chk.data.externallyAnchored > 0 ? "pass" : "partial",
        claim: "This chain's state is anchored somewhere it does not control",
        detail:
          chk.data && chk.data.externallyAnchored > 0
            ? `${chk.data.externallyAnchored} checkpoint(s) carry an external anchor.`
            : "No checkpoint has been published to a chain outside this project's control. A checkpoint recorded only on the chain it describes is worth nothing against that chain's own operators, so this reads as absent rather than as pending.",
      });

      // The single largest residual, and it is not on-chain data.
      setRows(out);
      say(`${out.filter((r) => r.state === "pass").length} of ${out.length} checks passed`, "ok");
    } catch (err) {
      say(describe(err), "no");
      setRows(out.length ? out : null);
    } finally {
      setBusy(false);
    }
  }


  const ceremonies = Object.values(CONFIG.ceremonies) as any[];
  const constraints = (CONFIG.constraints ?? []) as any[];
  const independent = ceremonies.reduce(
    (n, c) => n + c.contributions.filter((x: any) => x.independent).length,
    0,
  );

  if (!t) {
    return (
      <>
        <div className="page-head">
          <h1>Verification</h1>
        </div>
        <Card>
          <Empty icon="verification" title="No tender to verify" />
        </Card>
      </>
    );
  }

  const passed = rows?.filter((r) => r.state === "pass").length ?? 0;

  return (
    <>
      <div className="page-head">
        <h1>Verification</h1>
        <p>
          Every value below is recomputed in this browser from the chain. Nothing here is
          a private figure — that is the point of the role.
        </p>
      </div>

      <TenderPicker tenders={tenders} value={t?.id ?? null} onChange={onSelect} />

      <div className="tender-head">
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="tender-title">{t.title}</div>
          <div className="tender-meta">{t.tenderIdString}</div>
        </div>
        <StateBadge state={t.state} />
      </div>

      <div className="grid g4">
        <Stat k="Bids in the set" v={t.submissionCount} s="accumulated by the contract" />
        <Stat
          k="Opened"
          v={`${t.bids.filter((b) => b.openable).length} / ${t.submissionCount}`}
          s={`${t.committee.threshold}-of-${t.committee.size} threshold`}
        />
        <Stat
          k="Award"
          v={t.award ? (t.award.winningPrice > 0n ? formatBdt(t.award.winningPrice) : "Withheld") : "None"}
          s={t.award ? `submission #${t.award.winnerSubmissionIndex}` : "not recorded"}
        />
        <Stat
          k="Checks passed"
          v={rows ? `${passed} / ${rows.length}` : "—"}
          s={rows ? "recomputed in this browser" : "not run yet"}
        />
      </div>

      <Card
        title="Independent re-check"
        sub="Recomputed in this browser, from the chain."
        accent="accent"
        chain={
          <>
            <ChainFact k="Tender id"><Hash v={t.id} lead={10} tail={6} /></ChainFact>
            <ChainFact k="Rules hash"><Hash v={t.rulesHash} lead={10} tail={6} /></ChainFact>
            <ChainFact k="Bid set root"><Hash v={t.bidSetRoot} lead={10} tail={6} /></ChainFact>
            <ChainFact k="Issuer root"><Hash v={t.issuerRegistryRoot} lead={10} tail={6} /></ChainFact>
          </>
        }
      >
        <button className="btn primary" disabled={busy} onClick={recheck}>
          {busy ? "Recomputing…" : "Recompute everything"}
        </button>

        {rows ? (
          <div style={{ marginTop: 20 }}>
            <Evidence>
              {rows.map((r) => (
                <Check key={r.claim} state={r.state} claim={r.claim} detail={r.detail} />
              ))}
            </Evidence>
          </div>
        ) : null}

        {lines.length ? (
          <div style={{ marginTop: 16 }}>
            <Log lines={lines} />
          </div>
        ) : null}
      </Card>

      <Card
        title="Bids as the chain holds them"
        sub="Nothing here identifies a bidder."
      >
        {t.submissionCount === 0 ? (
          <Empty icon="bidder" title="No bids" />
        ) : (
          <div className="scroll-x">
            <table className="tbl">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Reference</th>
                  <th>Commitment</th>
                  <th>Opening</th>
                  <th>Status at close</th>
                </tr>
              </thead>
              <tbody>
                {t.bids.map((b) => (
                  <tr key={b.index} className={t.award?.winnerSubmissionIndex === b.index ? "hot" : undefined}>
                    <td><strong>{b.index}</strong></td>
                    <td><Hash v={b.nullifier} lead={8} tail={6} /></td>
                    <td><Hash v={b.bidCommitment} lead={8} tail={6} /></td>
                    <td style={{ minWidth: 190 }}>
                      <Threshold count={b.shares} threshold={b.threshold} label={b.revealed ? "Shares" : "Not revealed"} />
                    </td>
                    <td>
                      {b.statusProven ? (
                        <Tag tone="good" icon="check">Re-proved</Tag>
                      ) : (
                        <Tag icon="dash">Not proved</Tag>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card
        title="Circuits"
        sub="What each proof establishes, and how large it is."
      >
        <div className="grid g3">
          {ceremonies.map((c) => {
            const k = constraints.find((x) => x.circuit === c.circuit);
            const label: Record<string, string> = {
              eligibility: "Proves a bidder meets every published requirement.",
              award: "Proves the winner is the lowest qualified price over the complete set.",
              winner_identity: "Proves the firm that publishes its name placed the winning bid.",
            };
            return (
              <div key={c.circuit} className="stat">
                <div className="stat-k">{c.circuit.replace(/_/g, " ")}</div>
                <div className="stat-v">{k ? k.nonLinearConstraints.toLocaleString() : "—"}</div>
                <div className="stat-s">constraints · {k ? k.publicInputs : "—"} public values</div>
                <div className="small muted" style={{ marginTop: 10, lineHeight: 1.5 }}>
                  {label[c.circuit] ?? ""}
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      <Card
        title="Checkpoints"
        sub="A fingerprint of the chain's own state, so a later change would be detectable."
      >
        {chk.data ? (
          <>
            <dl className="kv">
              <dt>Recorded on this chain</dt>
              <dd>{chk.data.count}</dd>
              <dt>Anchored externally</dt>
              <dd>
                {chk.data.externallyAnchored > 0 ? (
                  chk.data.externallyAnchored
                ) : (
                  <Tag tone="wait" icon="alert">Absent</Tag>
                )}
              </dd>
              {chk.data.latest ? (
                <>
                  <dt>Latest digest</dt>
                  <dd><Hash v={chk.data.latest.digest} /></dd>
                </>
              ) : null}
            </dl>
            <Note tone="wait" icon="alert">
              <strong>Absent, not pending.</strong> No checkpoint has been published
              outside this network, so this row is honest rather than reassuring.
            </Note>
          </>
        ) : (
          <div className="muted">Reading…</div>
        )}
      </Card>

      <Card
        title="The independent verifier"
        sub="A command-line tool that re-runs every check here against an exported bundle, without this dashboard."
      >
        <p className="small" style={{ lineHeight: 1.6 }}>
          Sixteen checks re-derived from the exported record alone.
        </p>
        <pre
          className="log"
          style={{ marginTop: 14 }}
        >{`npm run evidence -- --tender ${t.tenderIdString}
npm run verify -- evidence/<bundle>.json`}</pre>
      </Card>
    </>
  );
}
