/**
 * Authority — the procuring entity's console.
 *
 * Create a tender, watch submissions arrive, open the bids after the deadline,
 * declare the winner. Everything here is a real transaction on the chain, and
 * every one of them is refused by the contract if it is out of order — which is
 * the point worth making to anyone watching: the authority cannot open a bid
 * early, cannot edit a frozen rule, and cannot name a winner the circuit did
 * not select.
 */
import { useEffect, useMemo, useState } from "react";
import { Contract, keccak256, toUtf8Bytes } from "ethers";
import {
  combineInExponent,
  dealCommitteeKey,
  decryptionShare,
  emptyRevocationTree,
  fetchCiphertext,
  initBabyjub,
  initEddsa,
  initPoseidon,
  jcsCanonicalize,
  openSealedBid,
  proveDleq,
  toField,
  verifyDealing,
  verifyDleq,
  type OpenedBid,
} from "@fairproof/crypto";
import {
  abiOf,
  account,
  addressOf,
  anonymousSigner,
  contract,
  formatBdt,
  formatCountdown,
  formatTime,
  provider,
  roleLabel,
  send,
  shortHash,
  writeAs,
  REPLICAS,
} from "../lib/chain";
import { describe, useNow, usePoll } from "../lib/hooks";
import { issuerRegistry, proveAward } from "../lib/prover";
import { parseCiphertextBytes } from "../lib/ciphertext";
import { loadDealing, loadSeededDealings, saveDealing, type StoredDealing } from "../lib/vault";
import { CONFIG } from "../lib/chain";
import {
  Card,
  ChainFact,
  CheckList,
  Empty,
  Field,
  Hash,
  Log,
  Note,
  StateBadge,
  Stat,
  Steps,
  Tag,
  Threshold,
  Timeline,
  type LogLine,
} from "../components/kit";
import { Icon } from "../components/Icon";
import type { RoleProps } from "../App";

const AUTHORITY = "tender-authority";
const COUNCIL = "council-regulator";
const COMMITTEE = [1, 2, 3, 4, 5].map((i) => `committee-${i}`);
const ZERO32 = "0x" + "00".repeat(32);
const hex32 = (v: bigint) => "0x" + v.toString(16).padStart(64, "0");

/** Epoch seconds -> the "YYYY-MM-DDTHH:mm" a datetime-local input expects, in
 * local time. Built by hand because toISOString() would shift it to UTC. */
function toLocalInput(epoch: number): string {
  const d = new Date(epoch * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** A span of seconds, read out the way someone setting a deadline thinks. */
function formatSpan(secs: number): string {
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return m % 60 ? `${h}h ${m % 60}m` : `${h}h`;
  return `${Math.floor(h / 24)} days`;
}

/** The council-held preconditions a tender cannot be published without. */
async function readPreflight(epoch: number) {
  const tr = contract("TenderRegistry");
  const reg = contract("IssuerRegistry");
  const [isAuthority, minWindow, absoluteMin, currentEpoch, epochIssuerRoot, epochRevRoot] =
    await Promise.all([
      tr.isTenderAuthority(account(AUTHORITY).address),
      tr.minReviewWindow(),
      tr.ABSOLUTE_MIN_REVIEW_WINDOW(),
      reg.currentEpoch(),
      reg.issuerRegistryRoot(epoch),
      reg.revocationRoot(epoch),
    ]);
  const currentRevRoot = await reg.revocationRoot(currentEpoch);
  return {
    isAuthority: isAuthority as boolean,
    minWindow: Number(minWindow),
    absoluteMin: Number(absoluteMin),
    currentEpoch: Number(currentEpoch),
    ready:
      (isAuthority as boolean) &&
      epochIssuerRoot !== ZERO32 &&
      epochRevRoot !== ZERO32 &&
      currentRevRoot !== ZERO32,
  };
}

const STEPS = [
  { n: "1", title: "Create the tender", detail: "reserves the reference" },
  { n: "2", title: "Publish the rules", detail: "the full document, on-chain" },
  { n: "3", title: "Freeze the rules", detail: "the contract hashes what it stored" },
  { n: "4", title: "Set the requirements", detail: "the values the proof will check" },
  { n: "5", title: "Appoint the committee", detail: "three of five, verified on-chain" },
  { n: "6", title: "Activate", detail: "every rule locked from this block" },
];
type StepState = "todo" | "on" | "ok" | "bad";

export default function Authority({ tenders, selected, section, onSelect, goto, refresh }: RoleProps) {
  const now = useNow();
  const [lines, setLines] = useState<LogLine[]>([]);
  const [busy, setBusy] = useState(false);
  const say = (text: string, kind: LogLine["kind"] = "dim") =>
    setLines((l) => [...l, { text, kind }]);

  const t = selected;

  // ------------------------------------------------------------- create
  // Nothing is filled in for the officer. What a tender is for, who is buying
  // and what it requires are the whole content of the act — pre-filling them
  // invites publishing somebody else's numbers by accident.
  const [title, setTitle] = useState("");
  const [buyer, setBuyer] = useState("");
  const [location, setLocation] = useState("");
  const [reference, setReference] = useState("");
  const [turnover, setTurnover] = useState("");
  const [experience, setExperience] = useState("");
  const [certCode, setCertCode] = useState("");
  const [reviewWindow, setReviewWindow] = useState("60");
  const [leadTime, setLeadTime] = useState("150");
  // The deadline is picked as a wall-clock instant. Held as epoch seconds and
  // seeded once, so it does not drift as the page's clock ticks.
  const [deadlineAt, setDeadlineAt] = useState(
    () => Math.floor(Date.now() / 1000) + 60 + 150 + 600,
  );
  const EPOCH = 21n;

  const pre = usePoll(() => readPreflight(Number(EPOCH)), 6000);
  const [stepStates, setStepStates] = useState<StepState[]>(() => STEPS.map(() => "todo"));
  const [published, setPublished] = useState<string | null>(null);
  const [publishedRef, setPublishedRef] = useState<string | null>(null);

  // Bidding opens this far ahead, by the browser's clock; publish() re-anchors
  // the same span on the chain's.
  const projectedStart = now + Number(reviewWindow || "0") + Number(leadTime || "0");
  const windowSecs = deadlineAt - projectedStart;

  const nums = {
    turnover: BigInt(turnover || "0"),
    experience: BigInt(experience || "0"),
    certCode: BigInt(certCode || "0"),
    reviewWindow: BigInt(reviewWindow || "0"),
    leadTime: BigInt(leadTime || "0"),
    biddingWindow: BigInt(Math.max(0, windowSecs)),
  };
  const problems: string[] = [];
  if (title.trim().length < 6) problems.push("Give the tender a title.");
  if (buyer.trim().length < 2) problems.push("Name the buying authority.");
  if (location.trim().length < 2) problems.push("Give a location.");
  if (!/^[\x20-\x7e]{4,64}$/.test(reference)) problems.push("Give the tender a reference.");
  if (!experience.trim()) problems.push("Set the required experience in months.");
  if (!certCode.trim()) problems.push("Set the required certification code.");
  // After a successful publish the form still holds the reference it just used,
  // and the poll has by then returned the tender it created — so this check
  // would flag the office's own new tender. Exempt exactly that one.
  if (reference !== publishedRef && tenders.some((x) => x.tenderIdString === reference))
    problems.push("That reference already exists.");
  if (nums.turnover <= 0n) problems.push("The turnover threshold must be above zero.");
  if (nums.turnover > BigInt(Number.MAX_SAFE_INTEGER))
    problems.push("The turnover threshold is too large to record exactly.");
  if (pre.data && nums.reviewWindow < BigInt(pre.data.minWindow))
    problems.push(`The review window is below the policy floor of ${pre.data.minWindow}s.`);
  if (nums.leadTime < 120n) problems.push("Allow at least 120s of lead time.");
  if (windowSecs < 60) problems.push("Bidding must close at least 60s after it opens.");

  const issuerLabel = "ICAB Registered Audit Firm";
  const issuerId = useMemo(() => keccak256(toUtf8Bytes(`ISSUER-${issuerLabel}`)), []);

  async function prepare() {
    setBusy(true);
    setLines([]);
    try {
      await initPoseidon();
      await initEddsa();
      await initBabyjub();
      const tr = writeAs("TenderRegistry", COUNCIL);
      const read = contract("TenderRegistry");
      const regRead = contract("IssuerRegistry");
      const reg = writeAs("IssuerRegistry", COUNCIL);

      if (!(await read.isTenderAuthority(account(AUTHORITY).address))) {
        await send(tr.setTenderAuthority, [account(AUTHORITY).address, true]);
        say("procuring authority authorised", "ok");
      }
      const absoluteMin = await read.ABSOLUTE_MIN_REVIEW_WINDOW();
      if ((await read.minReviewWindow()) > absoluteMin) {
        await send(tr.setMinReviewWindow, [
          absoluteMin,
          "Lower the review-window floor to the contract's hard constant",
        ]);
        say(`review-window floor set to ${absoluteMin}s`, "ok");
      }

      const registry = issuerRegistry();
      const empty = emptyRevocationTree();
      // getIssuer REVERTS for an unknown id rather than reporting registered:false.
      let registered = false;
      try {
        registered = (await regRead.getIssuer(issuerId)).registered;
      } catch {
        registered = false;
      }
      if (!registered) {
        await send(reg.registerIssuer, [
          issuerId,
          registry.issuerKey.x,
          registry.issuerKey.y,
          1,
          issuerLabel,
        ]);
      }
      if ((await regRead.issuerRegistryRoot(EPOCH)) === ZERO32) {
        await send(reg.publishIssuerRegistryRoot, [EPOCH, hex32(registry.root)]);
      }
      if ((await regRead.revocationRoot(EPOCH)) === ZERO32) {
        await send(reg.publishRevocationRoot, [EPOCH, hex32(empty.root)]);
      }
      // closeTender pins the CURRENT epoch's root; without one the tender would
      // become permanently unclosable.
      const current = await regRead.currentEpoch();
      if ((await regRead.revocationRoot(current)) === ZERO32) {
        await send(reg.publishRevocationRoot, [current, hex32(empty.root)]);
      }
      say("certifying body registered and its records published", "ok");
      pre.refresh();
      refresh();
    } catch (err) {
      say(describe(err), "no");
    } finally {
      setBusy(false);
    }
  }

  async function publish() {
    setBusy(true);
    setLines([]);
    setPublished(null);
    const states: StepState[] = STEPS.map(() => "todo");
    const mark = (i: number, s: StepState) => {
      states[i] = s;
      setStepStates([...states]);
    };
    try {
      await initPoseidon();
      await initEddsa();
      await initBabyjub();
      const tr = writeAs("TenderRegistry", AUTHORITY);
      const read = contract("TenderRegistry");

      // The chain's clock, not the browser's: a window computed against a
      // skewed local clock is rejected at activation for a reason that reads
      // like a policy failure.
      const block = await provider.getBlock("latest");
      const chainNow = BigInt(block!.timestamp);
      const biddingStart = chainNow + nums.reviewWindow + nums.leadTime;
      const deadline = biddingStart + nums.biddingWindow;

      const ruleDoc = jcsCanonicalize({
        awardRule: "LOWEST_QUALIFIED_PRICE",
        biddingStart: Number(biddingStart),
        buyer,
        contingencyPolicy: "CANCEL_AND_REISSUE",
        deadline: Number(deadline),
        disclosurePolicy: "PUBLISH_WINNING_PRICE",
        issuerEpoch: Number(EPOCH),
        location,
        requirements: {
          certificationCode: Number(nums.certCode),
          experienceMonths: Number(nums.experience),
          turnoverThreshold: Number(nums.turnover),
        },
        revocationPolicy: "DEADLINE_ROOT",
        reviewWindow: Number(nums.reviewWindow),
        schemaVersion: 1,
        selectionRule: "LOWEST_QUALIFIED_PRICE",
        tenderId: reference,
        tieBreakRule: "SUBMISSION_SEQUENCE",
        title,
        verifierVersion: 1,
      });
      const localHash = keccak256(toUtf8Bytes(ruleDoc));
      const tenderId = keccak256(toUtf8Bytes(reference));

      mark(0, "on");
      await send(tr.createTender, [reference]);
      say(`created · ${reference}`, "ok");
      mark(0, "ok");

      mark(1, "on");
      await send(tr.setRuleDocument, [tenderId, toUtf8Bytes(ruleDoc)]);
      say(`rules published · ${ruleDoc.length} bytes on-chain`, "ok");
      mark(1, "ok");

      mark(2, "on");
      const recomputed = await read.recomputeRulesHash(tenderId);
      if (recomputed !== localHash) {
        mark(2, "bad");
        throw new Error("the contract recomputed a different hash from the document it stored");
      }
      say(`rules frozen · ${shortHash(recomputed)}`, "ok");
      mark(2, "ok");

      mark(3, "on");
      await send(tr.setRuleFields, [
        tenderId,
        {
          requirements: {
            turnoverThreshold: nums.turnover,
            experienceMonths: Number(nums.experience),
            certificationCode: nums.certCode,
          },
          biddingStart,
          deadline,
          requiredIssuerId: issuerId,
          issuerEpoch: EPOCH,
          schemaVersion: 1,
          verifierVersion: 1,
          disclosurePolicy: 1,
          awardRule: 1,
          tieBreakRule: 1,
          contingencyPolicy: 1,
          reviewWindow: nums.reviewWindow,
        },
      ]);
      say("requirements set", "ok");
      mark(3, "ok");

      mark(4, "on");
      const dealt = dealCommitteeKey();
      const check = verifyDealing(dealt);
      if (!check.ok) {
        mark(4, "bad");
        throw new Error(check.problems.join("; "));
      }
      const members = COMMITTEE.map((r) => account(r).address);
      await send(tr.setCommitteeKey, [
        tenderId,
        dealt.publicKey.x,
        dealt.publicKey.y,
        members,
        dealt.shares.map((s) => s.publicShare.x),
        dealt.shares.map((s) => s.publicShare.y),
        dealt.commitments.map((c) => c.x),
        dealt.commitments.map((c) => c.y),
      ]);
      saveDealing({
        tenderId,
        tenderIdString: reference,
        dealtAt: Date.now(),
        publicKey: { x: dealt.publicKey.x.toString(), y: dealt.publicKey.y.toString() },
        commitments: dealt.commitments.map((c) => ({ x: c.x.toString(), y: c.y.toString() })),
        shares: dealt.shares.map((s) => ({
          index: s.index,
          share: s.share.toString(),
          publicShareX: s.publicShare.x.toString(),
          publicShareY: s.publicShare.y.toString(),
        })),
        members,
      });
      say("opening committee appointed — the contract verified the key", "ok");
      mark(4, "ok");

      mark(5, "on");
      const r = await send(tr.activateTender, [tenderId, localHash]);
      say(`ACTIVE · block ${r.blockNumber} · rules locked`, "ok");
      say(`bidding opens ${formatTime(biddingStart)}, closes ${formatTime(deadline)}`, "dim");
      mark(5, "ok");

      setPublished(tenderId);
      setPublishedRef(reference);
      onSelect(tenderId);
      refresh();
    } catch (err) {
      const i = states.findIndex((s) => s === "on");
      if (i >= 0) mark(i, "bad");
      say(describe(err), "no");
    } finally {
      setBusy(false);
    }
  }

  // ------------------------------------------------------------ opening
  const [seeded, setSeeded] = useState<StoredDealing[]>([]);
  useEffect(() => {
    let alive = true;
    loadSeededDealings().then((d) => alive && setSeeded(d));
    return () => {
      alive = false;
    };
  }, []);
  const dealing: StoredDealing | null = t
    ? loadDealing(t.id) ?? seeded.find((d) => d.tenderId === t.id) ?? null
    : null;
  const [opened, setOpened] = useState<Record<number, bigint>>({});

  async function closeTender() {
    setBusy(true);
    setLines([]);
    try {
      const tr = new Contract(
        addressOf("TenderRegistry"),
        abiOf("TenderRegistry") as never,
        anonymousSigner(),
      );
      const r = await send(tr.closeTender, [t!.id]);
      say(`bidding closed · block ${r.blockNumber}`, "ok");
      say("closed from an address holding no role — anyone may do this", "dim");
      refresh();
    } catch (err) {
      say(describe(err), "no");
    } finally {
      setBusy(false);
    }
  }

  async function openBid(index: number) {
    setBusy(true);
    setLines([]);
    try {
      await initPoseidon();
      await initBabyjub();
      const bid = t!.bids[index];
      const om = contract("OpeningManager");

      if (!bid.revealed) {
        const got = await fetchCiphertext(REPLICAS, bid.ciphertextHash);
        const w = new Contract(
          addressOf("OpeningManager"),
          abiOf("OpeningManager") as never,
          anonymousSigner(),
        );
        await send(w.revealCiphertext, [t!.id, index, got.bytes]);
        say(`bid #${index}: sealed envelope published and checked`, "ok");
      }

      const d = dealing;
      if (!d) throw new Error("no committee key material is available in this browser");
      const ct = await om.getCiphertext(t!.id, index);
      const R = { x: ct.rX, y: ct.rY };

      for (const m of [1, 2, 3]) {
        const already = await om.shareSubmitted(t!.id, index, m);
        if (already) continue;
        const share = d.shares.find((s) => s.index === m)!;
        const D = decryptionShare(BigInt(share.share), R);
        const proof = proveDleq({ secret: BigInt(share.share), ephemeral: R });
        if (
          !verifyDleq({
            publicShare: { x: BigInt(share.publicShareX), y: BigInt(share.publicShareY) },
            ephemeral: R,
            decryptionShare: D,
            proof,
          })
        ) {
          throw new Error(`member ${m}'s own proof does not verify`);
        }
        await send(writeAs("OpeningManager", `committee-${m}`).submitDecryptionShare, [
          t!.id,
          index,
          m,
          D.x,
          D.y,
          { aX: proof.a.x, aY: proof.a.y, bX: proof.b.x, bY: proof.b.y, z: proof.z },
        ]);
        const [, accepted, threshold, ready] = await om.openingStatus(t!.id, index);
        say(
          `bid #${index}: ${accepted} of ${threshold} committee members have acted`,
          ready ? "ok" : "wait",
        );
      }

      const shares = await om.getShares(t!.id, index);
      const shared = combineInExponent(
        [...shares].map((s: any) => ({ index: Number(s.memberIndex), point: { x: s.dX, y: s.dY } })),
      );
      const got = await fetchCiphertext(REPLICAS, bid.ciphertextHash);
      const result = await openSealedBid({
        ciphertext: parseCiphertextBytes(got.bytes),
        shared,
        expectedCommitment: bid.bidCommitment,
        tenderIdField: t!.tenderIdField,
        nullifier: bid.nullifier,
      });
      setOpened((o) => ({ ...o, [index]: result.bidAmount }));
      say(`bid #${index} opened · ${formatBdt(result.bidAmount)}`, "ok");
      refresh();
    } catch (err) {
      say(describe(err), "no");
    } finally {
      setBusy(false);
    }
  }

  const [cancelReason, setCancelReason] = useState("");

  /**
   * Cancel a tender. A council act, never the authority's own.
   *
   * Cancellation is not a rewrite: it ends the tender and records why. There
   * is deliberately no function anywhere that edits an active tender's rules,
   * so this is the only way out — and it is the oversight council's to take,
   * not the office that published it.
   */
  async function cancelTender() {
    setBusy(true);
    setLines([]);
    try {
      const tr = writeAs("TenderRegistry", COUNCIL);
      const r = await send(tr.cancelTender, [t!.id, cancelReason.trim()]);
      say(`tender cancelled · block ${r.blockNumber}`, "ok");
      say(`reason recorded on-chain: "${cancelReason.trim()}"`, "dim");
      setCancelReason("");
      refresh();
    } catch (err) {
      say(describe(err), "no");
    } finally {
      setBusy(false);
    }
  }

  // -------------------------------------------------------------- award
  const [awardProgress, setAwardProgress] = useState<number | null>(null);

  async function declareWinner() {
    setBusy(true);
    setLines([]);
    try {
      await initPoseidon();
      await initBabyjub();
      const d = dealing;
      if (!d) throw new Error("no committee key material is available in this browser");

      // Every accepted bid, opened, so the award is proved over the whole set.
      const om = contract("OpeningManager");
      const bids: OpenedBid[] = [];
      for (const b of t!.bids) {
        const shares = await om.getShares(t!.id, b.index);
        if (shares.length < b.threshold) {
          throw new Error(`bid #${b.index} has not been opened yet`);
        }
        const shared = combineInExponent(
          [...shares].map((s: any) => ({
            index: Number(s.memberIndex),
            point: { x: s.dX, y: s.dY },
          })),
        );
        const got = await fetchCiphertext(REPLICAS, b.ciphertextHash);
        const result = await openSealedBid({
          ciphertext: parseCiphertextBytes(got.bytes),
          shared,
          expectedCommitment: b.bidCommitment,
          tenderIdField: t!.tenderIdField,
          nullifier: b.nullifier,
        });
        bids.push({
          submissionIndex: b.index,
          nullifier: b.nullifier,
          bidAmount: result.bidAmount,
          bidNonce: result.bidNonce,
          ciphertextHashField: toField(b.ciphertextHash),
        });
      }
      say(`${bids.length} opened bids assembled`, "ok");

      const award = await proveAward({
        bids,
        tenderIdString: t!.tenderIdString,
        rulesHash: t!.rulesHash,
        expectedBidSetRoot: t!.bidSetRoot,
        onStage: (s) => say(s, "wait"),
        onProgress: (loaded, total) => setAwardProgress(Math.round((loaded / total) * 100)),
      });
      setAwardProgress(null);
      say(
        `award proved in ${(award.provingMs / 1000).toFixed(1)}s over the complete set`,
        "ok",
      );

      const r = await send(writeAs("AwardManager", AUTHORITY).recordAward, [
        t!.id,
        award.witness.winnerCommitment,
        award.witness.winningPrice,
        Number(award.witness.winnerIndex),
        award.pA,
        award.pB,
        award.pC,
      ]);
      say(
        `winner declared: submission #${award.witness.winnerIndex} at ${formatBdt(award.witness.winningPrice)} · block ${r.blockNumber}`,
        "ok",
      );
      refresh();
    } catch (err) {
      say(describe(err), "no");
      setAwardProgress(null);
    } finally {
      setBusy(false);
    }
  }

  // =====================================================================
  if (section === "create") {
    const ready = !!pre.data?.ready && problems.length === 0;
    return (
      <>
        <div className="page-head">
          <h1>Create tender</h1>
          <p>
            Once published, every requirement and date is locked. Nobody can change them.
          </p>
        </div>

        {pre.data && !pre.data.ready ? (
          <Card
            title="One-off setup"
            sub="Authorising this office and the certifying body. A council action."
            accent="wait"
          >
            <button className="btn primary" disabled={busy} onClick={prepare}>
              Run setup
            </button>
          </Card>
        ) : null}

        <div className="grid g2">
          <Card title="Tender details">
            <Field label="What the tender is for">
              <input
                className="in"
                placeholder="e.g. Construction of a 2 km rural road"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                disabled={busy}
              />
            </Field>
            <div className="row2">
              <Field label="Buying authority">
                <input
                  className="in"
                  placeholder="e.g. Roads and Highways Division"
                  value={buyer}
                  onChange={(e) => setBuyer(e.target.value)}
                  disabled={busy}
                />
              </Field>
              <Field label="Location">
                <input
                  className="in"
                  placeholder="e.g. Rangpur Sadar, Rangpur"
                  value={location}
                  onChange={(e) => setLocation(e.target.value)}
                  disabled={busy}
                />
              </Field>
            </div>
            <Field label="Reference" hint="Your own filing reference. It must be unique.">
              <div className="row" style={{ gap: 8, flexWrap: "nowrap" }}>
                <input
                  className="in mono"
                  placeholder="e.g. RHD-2026-0147"
                  value={reference}
                  onChange={(e) => setReference(e.target.value)}
                  disabled={busy}
                />
                <button
                  className="btn sm"
                  disabled={busy}
                  onClick={() =>
                    setReference(
                      `RHD-${new Date().getFullYear()}-${String(
                        Math.floor(Math.random() * 9000) + 1000,
                      )}`,
                    )
                  }
                >
                  Generate
                </button>
              </div>
            </Field>
          </Card>

          <Card title="Requirements and timing" sub="These become the values the proof checks.">
            <Field
              label="Minimum annual turnover (BDT)"
              hint={turnover ? formatBdt(nums.turnover) : "In taka."}
            >
              <input
                className="in mono"
                placeholder="e.g. 500000000"
                value={turnover}
                onChange={(e) => setTurnover(e.target.value.replace(/\D/g, ""))}
                disabled={busy}
              />
            </Field>
            <div className="row2">
              <Field label="Minimum experience (months)">
                <input
                  className="in mono"
                  placeholder="e.g. 60"
                  value={experience}
                  onChange={(e) => setExperience(e.target.value.replace(/\D/g, ""))}
                  disabled={busy}
                />
              </Field>
              <Field label="Required certification code">
                <input
                  className="in mono"
                  placeholder="e.g. 9001"
                  value={certCode}
                  onChange={(e) => setCertCode(e.target.value.replace(/\D/g, ""))}
                  disabled={busy}
                />
              </Field>
            </div>
            <div className="row2">
              <Field label="Public review window" hint="Seconds. Cannot be shortened later.">
                <input
                  className="in mono"
                  value={reviewWindow}
                  onChange={(e) => setReviewWindow(e.target.value.replace(/\D/g, ""))}
                  disabled={busy}
                />
              </Field>
              <Field
                label="Bidding closes"
                hint={
                  windowSecs >= 60
                    ? `Stays open ${formatSpan(windowSecs)} after it opens.`
                    : "Must be at least 60s after bidding opens."
                }
              >
                <input
                  className="in mono"
                  type="datetime-local"
                  value={toLocalInput(deadlineAt)}
                  min={toLocalInput(projectedStart + 60)}
                  onChange={(e) => {
                    const t = Date.parse(e.target.value);
                    if (!Number.isNaN(t)) setDeadlineAt(Math.floor(t / 1000));
                  }}
                  disabled={busy}
                />
              </Field>
            </div>
            <Field label="Lead time before bidding opens" hint="Seconds beyond the review window. Keep at least 120.">
              <input
                className="in mono"
                value={leadTime}
                onChange={(e) => setLeadTime(e.target.value.replace(/\D/g, ""))}
                disabled={busy}
              />
            </Field>
          </Card>
        </div>

        <Card title="Publish">
          {problems.length ? (
            <Note tone="wait" icon="alert">
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {problems.map((x) => (
                  <li key={x}>{x}</li>
                ))}
              </ul>
            </Note>
          ) : null}

          <Steps steps={STEPS.map((s, i) => ({ ...s, state: stepStates[i] }))} />

          <div className="row" style={{ marginTop: 18, gap: 12 }}>
            <button className="btn primary lg" disabled={busy || !ready} onClick={publish}>
              {busy ? "Publishing…" : "Publish tender"}
            </button>
            {published ? (
              <button className="btn" onClick={() => goto("authority", "manage", published)}>
                View it <Icon name="arrow" size={15} />
              </button>
            ) : null}
          </div>

          {lines.length ? (
            <div style={{ marginTop: 16 }}>
              <Log lines={lines} />
            </div>
          ) : null}
        </Card>
      </>
    );
  }

  // =====================================================================
  if (section === "manage") {
    const rows = tenders;
    return (
      <>
        <div className="page-head">
          <h1>Tenders</h1>
          <p>Everything this office has published. Select one to manage it.</p>
        </div>

        <div className="grid g4">
          <Stat k="Active" v={rows.filter((x) => x.state === 2).length} s="accepting bids" />
          <Stat k="Closed" v={rows.filter((x) => x.state >= 3 && x.state !== 6).length} s="past the deadline" />
          <Stat k="Awarded" v={rows.filter((x) => x.award).length} s="winner declared" />
          <Stat
            k="Bids received"
            v={rows.reduce((n, x) => n + x.submissionCount, 0)}
            s="sealed, unreadable"
          />
        </div>

        <Card title="All tenders">
          {rows.length === 0 ? (
            <Empty icon="doc" title="Nothing published yet">
              <button className="btn primary sm" onClick={() => goto("authority", "create")}>
                Create the first one
              </button>
            </Empty>
          ) : (
            <div className="scroll-x">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Tender</th>
                    <th className="num">Bids</th>
                    <th>Deadline</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((x) => (
                    <tr
                      key={x.id}
                      className={`click${x.id === t?.id ? " hot" : ""}`}
                      onClick={() => onSelect(x.id)}
                    >
                      <td>
                        <strong>{x.title}</strong>
                        <div className="tiny muted" style={{ marginTop: 2 }}>{x.tenderIdString}</div>
                      </td>
                      <td className="num">{x.submissionCount}</td>
                      <td>
                        <div className="small">{formatTime(x.deadline)}</div>
                        <div className="tiny muted">{formatCountdown(x.deadline, now)}</div>
                      </td>
                      <td><StateBadge state={x.state} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {t ? (
          <Card
            title={t.title}
            sub={`${t.tenderIdString} · ${t.buyer}`}
            right={<StateBadge state={t.state} />}
            chain={
              <>
                <ChainFact k="Rules hash"><Hash v={t.rulesHash} lead={10} tail={6} /></ChainFact>
                <ChainFact k="Rules"><Tag tone="good" icon="lock">Locked</Tag></ChainFact>
              </>
            }
          >
            <dl className="kv">
              <dt>Requirements</dt>
              <dd>
                {formatBdt(t.turnoverThreshold)} turnover · {t.experienceMonths} months ·
                certification {t.certificationCode.toString()}
              </dd>
              <dt>Bidding</dt>
              <dd>{formatTime(t.biddingStart)} → {formatTime(t.deadline)}</dd>
              <dt>Submissions</dt>
              <dd>{t.submissionCount} sealed</dd>
            </dl>

            <div className="row" style={{ marginTop: 18, gap: 10 }}>
              <button className="btn primary" onClick={() => goto("authority", "opening", t.id)}>
                Bid opening <Icon name="arrow" size={15} />
              </button>
              <button className="btn" onClick={() => goto("authority", "award", t.id)}>
                Award
              </button>
              <button className="btn" onClick={() => goto("public", "report", t.id)}>
                Public report
              </button>
            </div>
          </Card>
        ) : null}

        {t && t.state !== 5 && t.state !== 6 ? (
          <Card
            title="Cancel this tender"
            sub="Ends it and records why. There is no way to edit an active tender's rules — cancelling and reissuing is the only route, and it belongs to the oversight council."
            accent="bad"
          >
            <Field label="Reason" hint="Required, and published on-chain with the cancellation.">
              <input
                className="in"
                placeholder="e.g. Requirements published in error"
                value={cancelReason}
                onChange={(e) => setCancelReason(e.target.value)}
                disabled={busy}
              />
            </Field>
            <button
              className="btn"
              style={{ borderColor: "var(--bad-line)", color: "var(--bad)" }}
              disabled={busy || cancelReason.trim().length < 4}
              onClick={cancelTender}
            >
              <Icon name="cross" size={16} /> Cancel tender
            </button>
          </Card>
        ) : null}

        {lines.length ? <Card title="Activity"><Log lines={lines} /></Card> : null}
      </>
    );
  }

  // =====================================================================
  if (section === "opening") {
    if (!t) {
      return (
        <>
          <div className="page-head"><h1>Bid opening</h1></div>
          <Card><Empty icon="committee" title="No tender selected" /></Card>
        </>
      );
    }
    const past = now >= t.deadline;
    const revealed = t.bids.filter((b) => b.revealed).length;
    const openable = t.bids.filter((b) => b.openable).length;

    return (
      <>
        <div className="page-head">
          <h1>Bid opening</h1>
          <p>
            After the deadline, three of five committee members open each bid together.
          </p>
        </div>

        <div className="tender-head">
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="tender-title">{t.title}</div>
            <div className="tender-meta">{t.tenderIdString} · {t.submissionCount} sealed bids</div>
          </div>
          <StateBadge state={t.state} />
        </div>

        <Card title="Progress">
          <Timeline
            items={[
              {
                title: "Bidding closes",
                meta: `${formatTime(t.deadline)} · ${formatCountdown(t.deadline, now)}`,
                state: past ? "done" : "active",
              },
              {
                title: "Tender closed",
                meta: t.state >= 3 ? "closed, and the credential records pinned" : "anyone may close it once the deadline passes",
                state: t.state >= 3 ? "done" : past ? "active" : "todo",
              },
              {
                title: "Envelopes published",
                meta: `${revealed} of ${t.submissionCount}`,
                state: revealed === t.submissionCount && t.submissionCount > 0 ? "done" : t.state >= 3 ? "active" : "todo",
              },
              {
                title: "Bids opened",
                meta: `${openable} of ${t.submissionCount}`,
                state: openable === t.submissionCount && t.submissionCount > 0 ? "done" : revealed > 0 ? "active" : "todo",
              },
            ]}
          />
          {past && t.state === 2 ? (
            <div className="row" style={{ marginTop: 18 }}>
              <button className="btn primary" disabled={busy} onClick={closeTender}>
                Close bidding
              </button>
              <span className="small muted">Signed by an address with no role — anyone may do this.</span>
            </div>
          ) : null}
        </Card>

        {!past ? (
          <Note tone="wait" icon="clock">
            <strong>The deadline has not passed.</strong> Bidding closes{" "}
            {formatCountdown(t.deadline, now)}. Until then an early opening is impossible
            rather than merely prohibited.
          </Note>
        ) : null}

        {!dealing && past ? (
          <Note tone="wait" icon="alert">
            This browser holds no committee key material for this tender, so it can show
            the opening but cannot take part in it.
          </Note>
        ) : null}

        {t.submissionCount === 0 ? (
          <Card><Empty icon="bidder" title="No bids were submitted" /></Card>
        ) : (
          t.bids.map((b) => (
            <Card
              key={b.index}
              title={`Submission #${b.index}`}
              sub={`Received ${formatTime(b.submittedAt)}`}
              accent={b.openable ? "good" : b.revealed ? "wait" : "neutral"}
              chain={
                <>
                  <ChainFact k="Reference"><span className="mono">{shortHash(b.nullifier, 8, 6)}</span></ChainFact>
                  <ChainFact k="Envelope"><Hash v={b.ciphertextHash} lead={8} tail={6} /></ChainFact>
                </>
              }
              right={
                b.openable ? (
                  <Tag tone="good" icon="check" lg>Opened</Tag>
                ) : (
                  <Tag tone="accent" icon="lock" lg>Sealed</Tag>
                )
              }
            >
              <Threshold count={b.shares} threshold={b.threshold} label="Committee members who have acted" />

              {opened[b.index] !== undefined ? (
                <div style={{ marginTop: 16 }}>
                  <div className="eyebrow">Bid amount</div>
                  <div className="big-num" style={{ marginTop: 4 }}>{formatBdt(opened[b.index])}</div>
                  <div className="small muted" style={{ marginTop: 4 }}>
                    The opened price reproduces the commitment recorded at submission, so
                    it cannot have been altered.
                  </div>
                </div>
              ) : null}

              {past && t.state >= 3 && !b.openable && dealing ? (
                <button
                  className="btn primary"
                  style={{ marginTop: 16 }}
                  disabled={busy}
                  onClick={() => openBid(b.index)}
                >
                  Open this bid
                </button>
              ) : null}
            </Card>
          ))
        )}

        {lines.length ? (
          <Card title="Activity"><Log lines={lines} /></Card>
        ) : null}
      </>
    );
  }

  // =====================================================================
  // Award
  if (!t) {
    return (
      <>
        <div className="page-head"><h1>Award</h1></div>
        <Card><Empty icon="seal" title="No tender selected" /></Card>
      </>
    );
  }
  const allOpened = t.submissionCount > 0 && t.bids.every((b) => b.openable);
  const statusCount = t.bids.filter((b) => b.statusProven).length;
  const statusDone = t.submissionCount > 0 && statusCount === t.submissionCount;

  return (
    <>
      <div className="page-head">
        <h1>Award</h1>
        <p>
          The winner is selected by the rule published with the tender. This office cannot name anyone else.
        </p>
      </div>

      <div className="tender-head">
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="tender-title">{t.title}</div>
          <div className="tender-meta">{t.tenderIdString} · {t.submissionCount} bids</div>
        </div>
        <StateBadge state={t.state} />
      </div>

      {t.award ? (
        <Card
          title="Winner declared"
          accent="good"
          sub="Proved against every accepted bid."
          chain={
            <>
              <ChainFact k="Bid set root"><Hash v={t.award.bidSetRoot} lead={10} tail={6} /></ChainFact>
              <ChainFact k="Recorded"><span className="mono">{formatTime(t.award.awardedAt)}</span></ChainFact>
              <ChainFact k="Verified"><Tag tone="good" icon="check">Proof accepted</Tag></ChainFact>
            </>
          }
        >
          <div className="grid g3">
            <div>
              <div className="eyebrow">Winner</div>
              <div style={{ fontSize: 19, fontWeight: 650, marginTop: 5 }}>
                {t.identity?.legalName ?? `Submission #${t.award.winnerSubmissionIndex}`}
              </div>
            </div>
            <div>
              <div className="eyebrow">Winning price</div>
              <div className="big-num" style={{ marginTop: 5 }}>
                {t.award.winningPrice > 0n ? formatBdt(t.award.winningPrice) : "Withheld"}
              </div>
            </div>
            <div>
              <div className="eyebrow">Bids considered</div>
              <div className="big-num" style={{ marginTop: 5 }}>{t.award.submissionCount}</div>
            </div>
          </div>
          <div className="row" style={{ marginTop: 18 }}>
            <button className="btn" onClick={() => goto("public", "report", t.id)}>
              Publish the report <Icon name="arrow" size={15} />
            </button>
          </div>
        </Card>
      ) : (
        <Card title="Declare the winner" sub="Available once every bid has been opened.">
          <CheckList
            items={[
              { label: "Bidding closed", state: t.state >= 3 ? "pass" : "pending" },
              {
                label: "All bids opened",
                state: allOpened ? "pass" : "pending",
                value: `${t.bids.filter((b) => b.openable).length} of ${t.submissionCount}`,
              },
              {
                label: "Bidders confirmed eligible at the deadline",
                state: statusDone ? "pass" : "pending",
                value: `${statusCount} of ${t.submissionCount}`,
              },
              { label: "Committee key available", state: dealing ? "pass" : "pending" },
            ]}
          />

          {allOpened && !statusDone ? (
            <Note tone="wait" icon="clock">
              <strong>Waiting on the bidders.</strong> Each firm has to re-prove that its
              credential was still valid at the deadline, against the records pinned when
              bidding closed. Only they can — the proof needs a secret this office does
              not hold, and the contract refuses an award without it. They do it from
              their own <em>My bids</em> screen.
            </Note>
          ) : null}

          {awardProgress !== null ? (
            <div style={{ marginTop: 16 }}>
              <div className="spread" style={{ marginBottom: 6 }}>
                <span className="small">Preparing the selection proof</span>
                <span className="small muted num">{awardProgress}%</span>
              </div>
              <div className="meter"><i style={{ width: `${awardProgress}%` }} /></div>
            </div>
          ) : null}

          <button
            className="btn primary lg"
            style={{ marginTop: 18 }}
            disabled={busy || !allOpened || !statusDone || !dealing}
            onClick={declareWinner}
          >
            {busy ? "Working…" : "Declare winner"}
          </button>
          <div className="small muted" style={{ marginTop: 10 }}>
            The selection proof is generated in this browser. It takes about a minute the
            first time, because the circuit is 38 MB.
          </div>

          {lines.length ? (
            <div style={{ marginTop: 16 }}>
              <Log lines={lines} />
            </div>
          ) : null}
        </Card>
      )}
    </>
  );
}
