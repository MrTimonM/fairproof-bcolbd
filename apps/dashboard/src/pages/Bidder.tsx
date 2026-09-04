/**
 * Bidder — a bidding firm's own console.
 *
 * Four screens: what is open, the credential this firm holds, a bid, and what
 * happened to it. The zero-knowledge proof is generated in this browser tab —
 * the firm's turnover, experience and price are private inputs to it and are
 * never transmitted — but the interface says that once and then gets out of
 * the way. What a bidder actually wants to see is "Qualified", a box to type a
 * number into, and one button.
 */
import { useEffect, useMemo, useState } from "react";
import { Contract, Interface, toUtf8Bytes } from "ethers";
import {
  SCHEMA_VERSION,
  emptyRevocationTree,
  initBabyjub,
  initEddsa,
  initPoseidon,
  jcsCanonicalize,
  sealBid,
  subjectCommitment,
  uploadToReplicas,
} from "@fairproof/crypto";
import {
  abiOf,
  addressOf,
  anonymousSigner,
  CONFIG,
  contract,
  formatBdt,
  formatCountdown,
  formatTime,
  send,
  shortHash,
  REPLICAS,
} from "../lib/chain";
import { describe, useNow, usePoll } from "../lib/hooks";
import {
  boundTo,
  checkAttestation,
  commitmentFor,
  decodeAttestation,
  type Attestation,
} from "../lib/attestation";
import {
  issuerRegistry,
  loadCircuit,
  proveDeadlineStatus,
  proveEligibility,
  proveWinnerIdentity,
  randomSecret,
  signCredential,
} from "../lib/prover";
import {
  loadSeededReceipts,
  receiptsFor,
  saveReceipt,
  type BidReceipt,
} from "../lib/receipts";
import {
  Card,
  ChainFact,
  Check,
  CheckList,
  Empty,
  Evidence,
  Field,
  Hash,
  Log,
  Note,
  Privacy,
  Stat,
  StateBadge,
  Tag,
  TenderPicker,
  type LogLine,
} from "../components/kit";
import { Icon } from "../components/Icon";
import type { RoleProps } from "../App";

/**
 * Every contract in the submission path, merged into one interface.
 *
 * `submitBid` reverts with `ProofRejected`, declared in EligibilityVerifier —
 * a client decoding with SealedBid's ABI alone gets "unknown custom error" and
 * the reader learns nothing.
 */
const ERROR_ABI = new Interface(
  ["SealedBid", "EligibilityVerifier", "TenderRegistry", "IssuerRegistry"].flatMap((n) =>
    (abiOf(n) as { type: string }[]).filter((f) => f.type === "error"),
  ),
);
function explain(err: unknown): string {
  const anyErr = err as { data?: string; info?: { error?: { data?: string } } };
  const data = anyErr?.data ?? anyErr?.info?.error?.data;
  if (typeof data === "string" && data.startsWith("0x") && data.length >= 10) {
    try {
      const parsed = ERROR_ABI.parseError(data);
      if (parsed) return `${parsed.name}(${parsed.args.map(String).join(", ")})`;
    } catch {
      // Fall through to the plain message.
    }
  }
  return describe(err);
}

/**
 * The company registered in this browser.
 *
 * A firm enters this once. It is stored locally and never transmitted — the
 * proof asserts that these figures meet a tender's thresholds without
 * disclosing any of them.
 */
interface Company {
  firmName: string;
  registrationNumber: string;
  credentialId: string;
  annualTurnover: string;
  relevantExperience: string;
  certificationCode: string;
  validForDays: number;
  /**
   * This firm's subject secret, as a decimal string.
   *
   * Long-lived, unlike the per-bid nonce: a certifying body signs a commitment
   * to it, so rotating it would invalidate every credential the firm holds.
   * Reusing it across tenders is safe because the marker a bid publishes is
   * Poseidon(secret, tenderId) — tender-scoped, and unlinkable between tenders.
   */
  subjectSecret: string;
  /** A credential an accredited body issued, as handed over. Empty if none. */
  attestation: string;
  /** False until the firm has pressed Save at least once. */
  registered: boolean;
}

const CRED_KEY = "fairproof.company.v1";
const BLANK: Company = {
  firmName: "",
  registrationNumber: "",
  credentialId: "",
  annualTurnover: "",
  relevantExperience: "",
  certificationCode: "",
  validForDays: 365,
  subjectSecret: "",
  attestation: "",
  registered: false,
};

function readCompany(): Company {
  try {
    const raw = localStorage.getItem(CRED_KEY);
    return raw ? { ...BLANK, ...(JSON.parse(raw) as Company) } : BLANK;
  } catch {
    return BLANK;
  }
}
function writeCompany(c: Company) {
  try {
    localStorage.setItem(CRED_KEY, JSON.stringify(c));
  } catch {
    // Storage disabled. The form still works for this session.
  }
}

/** Replica health, because a bid cannot be accepted without a storage quorum. */
async function readReplicas() {
  return Promise.all(
    REPLICAS.map(async (r) => {
      try {
        const res = await fetch(`${r.url}/health`, { signal: AbortSignal.timeout(2500) });
        return { ...r, up: res.ok };
      } catch {
        return { ...r, up: false };
      }
    }),
  );
}

type Phase = "idle" | "proving" | "sealing" | "uploading" | "submitting" | "done" | "failed";

export default function Bidder({ tenders, selected, section, onSelect, goto, refresh }: RoleProps) {
  const now = useNow();
  const replicas = usePoll(readReplicas, 8000);
  const quorumUp = (replicas.data ?? []).filter((r) => r.up).length;

  const [cred, setCred] = useState<Company>(readCompany);
  const [draft, setDraft] = useState<Company>(readCompany);
  const [paste, setPaste] = useState("");
  const [importErr, setImportErr] = useState<string | null>(null);
  const [commitCopied, setCommitCopied] = useState(false);
  /** Poseidon has to be up before a commitment can be derived. */
  const [myCommitment, setMyCommitment] = useState<string>("");
  useEffect(() => {
    if (!cred.subjectSecret) {
      setMyCommitment("");
      return;
    }
    let alive = true;
    initPoseidon()
      .then(() => alive && setMyCommitment(commitmentFor(BigInt(cred.subjectSecret)).toString()))
      .catch(() => alive && setMyCommitment(""));
    return () => {
      alive = false;
    };
  }, [cred.subjectSecret]);
  const [saved, setSaved] = useState(false);
  const set = (k: keyof Company, v: string | number) =>
    setDraft((d) => ({ ...d, [k]: v }) as Company);
  const dirty = JSON.stringify(draft) !== JSON.stringify(cred);

  /** Take in a credential a certifying body issued, checking it here first. */
  function importCredential() {
    setImportErr(null);
    try {
      const parsed = decodeAttestation(paste);
      if (!checkAttestation(parsed)) {
        throw new Error("the signature on that credential does not verify");
      }
      if (!cred.subjectSecret) {
        throw new Error("register your company first, so a subject secret exists");
      }
      if (!boundTo(parsed, BigInt(cred.subjectSecret))) {
        throw new Error(
          "that credential was issued to a different firm — it is bound to another " +
            "subject commitment, and no proof from this browser can satisfy it",
        );
      }
      const next = { ...cred, attestation: paste.trim(), registered: true };
      writeCompany(next);
      setCred(next);
      setDraft(next);
      setPaste("");
    } catch (err) {
      setImportErr(describe(err));
    }
  }

  /** Drop the credential and fall back to self-declared figures. */
  function removeCredential() {
    const next = { ...cred, attestation: "" };
    writeCompany(next);
    setCred(next);
    setDraft(next);
  }

  function saveCompany() {
    // Minted here rather than at bid time: a body has to be able to sign a
    // commitment to it before the firm ever places a bid.
    const next = {
      ...draft,
      subjectSecret: draft.subjectSecret || randomSecret().toString(),
      registered: true,
    };
    writeCompany(next);
    setCred(next);
    setDraft(next);
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  }

  const [amount, setAmount] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [failedAt, setFailedAt] = useState<Phase | null>(null);
  const [lines, setLines] = useState<LogLine[]>([]);
  const [download, setDownload] = useState<{ what: string; pct: number } | null>(null);
  const [proofDone, setProofDone] = useState(false);
  const [submitted, setSubmitted] = useState<{ index: number; hash: string; block: number } | null>(
    null,
  );
  const say = (text: string, kind: LogLine["kind"] = "dim") =>
    setLines((l) => [...l, { text, kind }]);

  const [receipts, setReceipts] = useState<BidReceipt[]>([]);
  const [seeded, setSeeded] = useState<BidReceipt[]>([]);
  useEffect(() => {
    let alive = true;
    loadSeededReceipts().then((r) => alive && setSeeded(r));
    return () => {
      alive = false;
    };
  }, []);

  const open = useMemo(() => tenders.filter((x) => x.state === 2), [tenders]);

  /**
   * The tender on screen.
   *
   * Submit bid prefers one that is actually open: landing a bidder on a closed
   * tender with a disabled button, while another is accepting bids, reads as a
   * broken page. Every other section keeps the shared selection, because after
   * bidding closes "what happened to mine?" is the only question left.
   */
  const t =
    section === "submit"
      ? (selected && selected.state === 2 ? selected : open[0] ?? selected ?? null)
      : selected ?? open[0] ?? null;

  useEffect(() => {
    if (!t) {
      setReceipts([]);
      return;
    }
    const mine = receiptsFor(t.id);
    const extra = seeded.filter(
      (s) => s.tenderId === t.id && !mine.some((m) => m.nullifier === s.nullifier),
    );
    setReceipts([...mine, ...extra].sort((a, b) => a.submissionIndex - b.submissionIndex));
  }, [t?.id, seeded]);

  /** A follow-up action (deadline confirmation, identity) is running. */
  const [acting, setActing] = useState(false);
  const busy = acting || (phase !== "idle" && phase !== "done" && phase !== "failed");

  /**
   * The credential this browser will actually prove.
   *
   * When an accredited body has issued one, its SIGNED figures are the ones
   * that count and the firm's own entries become a display copy it cannot make
   * the circuit believe. That is the whole difference between attested and
   * self-declared, so it is derived in one place rather than checked ad hoc.
   */
  const att = useMemo<Attestation | null>(() => {
    if (!cred.attestation) return null;
    try {
      return decodeAttestation(cred.attestation);
    } catch {
      return null;
    }
  }, [cred.attestation]);

  const held = att
    ? {
        annualTurnover: att.fields.annualTurnover,
        relevantExperience: Number(att.fields.relevantExperience),
        certificationCode: att.fields.certificationCode,
        validUntil: Number(att.fields.credentialValidUntil),
      }
    : {
        annualTurnover: BigInt(cred.annualTurnover || "0"),
        relevantExperience: Number(cred.relevantExperience || "0"),
        certificationCode: BigInt(cred.certificationCode || "0"),
        validUntil: null as number | null,
      };

  /** Every clause the circuit will check, checked here first. */
  const clauses = t
    ? [
        {
          label: "Annual turnover",
          ok: held.annualTurnover >= t.turnoverThreshold,
          has: formatBdt(held.annualTurnover),
          needs: `at least ${formatBdt(t.turnoverThreshold)}`,
        },
        {
          label: "Relevant experience",
          ok: held.relevantExperience >= t.experienceMonths,
          has: `${held.relevantExperience} months`,
          needs: `at least ${t.experienceMonths} months`,
        },
        {
          label: "Certification",
          ok: held.certificationCode === t.certificationCode,
          has: `code ${held.certificationCode || "—"}`,
          needs: `code ${t.certificationCode.toString()}`,
        },
        {
          label: "Credential validity",
          // Checked against the DEADLINE, never against now: a bid placed
          // early on a credential that lapses first cannot win.
          ok: held.validUntil !== null ? held.validUntil >= t.deadline : cred.validForDays > 0,
          has:
            held.validUntil !== null
              ? held.validUntil >= t.deadline
                ? `valid until ${formatTime(held.validUntil)}`
                : `lapses ${formatTime(held.validUntil)}, before the deadline`
              : cred.validForDays >= 0
                ? `valid ${cred.validForDays} days past the deadline`
                : `lapsed ${Math.abs(cred.validForDays)} days before it`,
          needs: "valid at the deadline",
        },
      ]
    : [];
  const qualified = clauses.length > 0 && clauses.every((c) => c.ok);
  // `!submitted` matters as much as `!busy`: this tender has a receipt in hand,
  // and a second press would burn a fresh nullifier on a duplicate envelope the
  // contract then rejects.
  const canSubmit =
    !!t &&
    t.biddingOpen &&
    qualified &&
    quorumUp >= 2 &&
    !busy &&
    !submitted &&
    BigInt(amount || "0") > 0n;

  // ------------------------------------------------------------- the bid
  async function submit() {
    if (!t) return;
    let at: Phase = "proving";
    const enter = (p: Phase) => {
      at = p;
      setPhase(p);
    };
    setPhase("proving");
    setFailedAt(null);
    setLines([]);
    setProofDone(false);
    setSubmitted(null);

    try {
      await initPoseidon();
      await initEddsa();
      await initBabyjub();

      const empty = emptyRevocationTree();
      if (t.revocationRoot && BigInt(t.revocationRoot) !== empty.root) {
        throw new Error(
          "this tender's epoch published a revocation root this browser cannot build a path in",
        );
      }

      // The firm's own long-lived secret, minted at registration. A body has
      // signed a commitment to it, so it cannot be regenerated per bid.
      const subjectSecret = BigInt(cred.subjectSecret);
      const bidNonce = randomSecret();
      if (att && !boundTo(att, subjectSecret)) {
        throw new Error(
          "the credential in this browser was issued to a different subject — " +
            "ask the certifying body to reissue it against this firm's commitment",
        );
      }
      say(
        att
          ? `credential attested by ${att.issuerLabel} — neither it nor the price leaves this tab`
          : "credential and price prepared — neither leaves this tab",
        "ok",
      );

      say("fetching the proving circuit — 18 MB, cached afterwards", "wait");
      await loadCircuit((loaded, total, what) =>
        setDownload({ what, pct: Math.round((loaded / total) * 100) }),
      );
      setDownload(null);

      const proof = await proveEligibility({
        // Present only when a body issued one. proveEligibility then proves
        // ITS signed figures and ignores everything below.
        attestation: att ?? undefined,
        credential: {
          subjectSecret,
          annualTurnover: BigInt(cred.annualTurnover),
          relevantExperience: BigInt(cred.relevantExperience),
          credentialId: BigInt(cred.credentialId),
          certificationCode: BigInt(cred.certificationCode),
          validUntil: BigInt(t.deadline + cred.validForDays * 86400),
          issuedAt: BigInt(t.activatedAt || now) - 86400n,
        },
        tender: {
          tenderIdString: t.tenderIdString,
          rulesHash: t.rulesHash,
          turnoverThreshold: t.turnoverThreshold,
          experienceMonthsThreshold: BigInt(t.experienceMonths),
          requiredCertificationCode: t.certificationCode,
          deadline: BigInt(t.deadline),
          credentialEpoch: BigInt(t.issuerEpoch),
          revocationRoot: empty.root,
        },
        bidAmount: BigInt(amount),
        bidNonce,
        onStage: (s) => say(s, "wait"),
      });
      setProofDone(true);
      say(`proof generated in ${(proof.provingMs / 1000).toFixed(1)}s`, "ok");

      enter("sealing");
      const sealed = await sealBid({
        payload: {
          tenderId: t.tenderIdString,
          amountMinorUnit: amount,
          currency: "BDT",
          bidNonce: bidNonce.toString(),
          subjectCommitment: proof.witness.bidCommitment.toString(),
          createdAt: new Date().toISOString(),
        },
        tenderPublicKey: { x: t.committee.yX, y: t.committee.yY },
        tenderIdField: proof.witness.tenderIdField,
        nullifier: proof.witness.nullifier,
      });
      if (sealed.bidCommitment !== proof.publicSignals[11]) {
        throw new Error("the sealed price and the proof disagree — refusing to submit");
      }
      say("price encrypted to the opening committee", "ok");

      enter("uploading");
      const up = await uploadToReplicas(REPLICAS, sealed.canonicalBytes, sealed.ciphertextHash);
      if (!up.quorumMet) throw new Error("the storage quorum was not met");
      say(`stored — ${up.receipts.length} of ${REPLICAS.length} replicas signed`, "ok");

      enter("submitting");
      const wallet = anonymousSigner();
      const sb = new Contract(addressOf("SealedBid"), abiOf("SealedBid") as never, wallet);
      const args = [
        {
          tenderId: t.id,
          nullifier: proof.publicSignals[10],
          bidCommitment: proof.publicSignals[11],
          ciphertextHash: sealed.ciphertextHash,
        },
        up.receipts.map((r) => ({
          replicaId: r.replicaId,
          contentHash: r.contentHash,
          byteLength: BigInt(r.byteLength),
          signature: r.signature,
        })),
        proof.pA,
        proof.pB,
        proof.pC,
      ];
      const gas = await sb.submitBid.estimateGas(...args, { gasPrice: 0 });
      const tx = await sb.submitBid(...args, { gasPrice: 0, gasLimit: (gas * 3n) / 2n });
      const receipt = await tx.wait();
      const index = Number(await contract("SealedBid").submissionCount(t.id)) - 1;

      saveReceipt({
        tenderId: t.id,
        tenderIdString: t.tenderIdString,
        tenderTitle: t.title,
        firmName: cred.firmName,
        submissionIndex: index,
        nullifier: proof.publicSignals[10].toString(),
        bidCommitment: proof.publicSignals[11].toString(),
        ciphertextHash: sealed.ciphertextHash,
        amountMinorUnit: amount,
        bidNonce: bidNonce.toString(),
        subjectSecret: subjectSecret.toString(),
        credential: {
          credentialId: cred.credentialId,
          annualTurnover: cred.annualTurnover,
          relevantExperience: cred.relevantExperience,
          certificationCode: cred.certificationCode,
          validForDays: cred.validForDays,
          registrationNumber: cred.registrationNumber,
        },
        attestation: cred.attestation || undefined,
        txHash: receipt.hash,
        from: wallet.address,
        gasUsed: String(receipt.gasUsed),
        submittedAt: Math.floor(Date.now() / 1000),
      });
      setReceipts(receiptsFor(t.id));
      setSubmitted({ index, hash: receipt.hash, block: receipt.blockNumber });
      say(`accepted as submission #${index}`, "ok");
      setPhase("done");
      refresh();
    } catch (err) {
      say(explain(err), "no");
      setFailedAt(at);
      setPhase("failed");
      setDownload(null);
    }
  }

  /**
   * Re-prove that this credential was unrevoked at the deadline.
   *
   * The award cannot be recorded until the winner has done this — the contract
   * refuses it — and only the bidder can, because the proof needs the subject
   * secret. An authority confirming a bidder's standing on its behalf is
   * exactly what this makes impossible.
   */
  async function confirmStatus(r: BidReceipt) {
    setActing(true);
    setLines([]);
    try {
      if (!r.subjectSecret || !r.credential) {
        throw new Error(
          "this receipt predates deadline confirmation and has no secret stored",
        );
      }
      await initPoseidon();
      await initEddsa();
      await initBabyjub();
      const pinned = await contract("IssuerRegistry").deadlineRevocationRoot(t!.id);
      if (!pinned || BigInt(pinned) === 0n) {
        throw new Error("the tender has not been closed, so no root has been pinned");
      }
      say("re-proving against the records pinned when bidding closed", "wait");
      const proof = await proveDeadlineStatus({
        attestation: r.attestation ? decodeAttestation(r.attestation) : undefined,
        credential: {
          subjectSecret: BigInt(r.subjectSecret),
          annualTurnover: BigInt(r.credential.annualTurnover),
          relevantExperience: BigInt(r.credential.relevantExperience),
          credentialId: BigInt(r.credential.credentialId),
          certificationCode: BigInt(r.credential.certificationCode),
          validUntil: BigInt(t!.deadline + r.credential.validForDays * 86400),
          issuedAt: BigInt(t!.activatedAt) - 86400n,
        },
        tender: {
          tenderIdString: t!.tenderIdString,
          rulesHash: t!.rulesHash,
          turnoverThreshold: t!.turnoverThreshold,
          experienceMonthsThreshold: BigInt(t!.experienceMonths),
          requiredCertificationCode: t!.certificationCode,
          deadline: BigInt(t!.deadline),
          credentialEpoch: BigInt(t!.issuerEpoch),
          revocationRoot: BigInt(pinned),
        },
        bidAmount: BigInt(r.amountMinorUnit),
        bidNonce: BigInt(r.bidNonce),
        pinnedRoot: BigInt(pinned),
        onStage: (x) => say(x, "wait"),
      });
      const ds = new Contract(
        addressOf("DeadlineStatus"),
        abiOf("DeadlineStatus") as never,
        anonymousSigner(),
      );
      const rec = await send(ds.submitStatusProof, [
        t!.id,
        r.submissionIndex,
        proof.pA,
        proof.pB,
        proof.pC,
      ]);
      say(`confirmed still eligible at the deadline · block ${rec.blockNumber}`, "ok");
      refresh();
    } catch (err) {
      say(explain(err), "no");
    } finally {
      setActing(false);
    }
  }

  /** Publish the winner's identity, after proving ownership of the bid. */
  async function publishIdentity(r: BidReceipt) {
    setActing(true);
    setLines([]);
    try {
      if (!r.subjectSecret || !r.credential) {
        throw new Error("this receipt has no secret stored, so ownership cannot be proved");
      }
      await initPoseidon();
      await initEddsa();
      await initBabyjub();

      const registry = issuerRegistry();
      const secret = BigInt(r.subjectSecret);
      const validUntil = BigInt(t!.deadline + r.credential.validForDays * 86400);
      const fields = {
        schemaVersion: SCHEMA_VERSION,
        subjectCommitment: subjectCommitment(secret),
        annualTurnover: BigInt(r.credential.annualTurnover),
        relevantExperience: BigInt(r.credential.relevantExperience),
        certificationCode: BigInt(r.credential.certificationCode),
        certValidUntil: validUntil,
        credentialValidUntil: validUntil,
        credentialId: BigInt(r.credential.credentialId),
        issuerEpoch: BigInt(t!.issuerEpoch),
        issuedAt: BigInt(t!.activatedAt) - 86400n,
      };
      // An issued credential is proved as issued. Re-signing our own version
      // of it would assert a DIFFERENT credential and fail against the award.
      const issued = r.attestation ? decodeAttestation(r.attestation) : null;
      const proved = issued
        ? { fields: issued.fields, signature: issued.signature, key: issued.issuerPublicKey }
        : {
            fields,
            signature: signCredential(registry.issuerPriv, fields).signature,
            key: registry.issuerKey,
          };

      const record = {
        // From the credential actually proved: the circuit binds this id, so a
        // firm's own note of it must not be what the record publishes.
        credentialId: Number(proved.fields.credentialId),
        legalName: r.firmName,
        registrationNumber: r.credential.registrationNumber ?? "—",
        tradeLicence: "—",
        vatBin: "—",
      };
      say("proving that this firm placed the winning bid", "wait");
      const proof = await proveWinnerIdentity({
        credential: {
          fields: proved.fields,
          signature: proved.signature,
          issuerPublicKey: proved.key,
        },
        subjectSecret: secret,
        bidAmount: BigInt(r.amountMinorUnit),
        bidNonce: BigInt(r.bidNonce),
        tenderIdString: t!.tenderIdString,
        record,
        onStage: (x) => say(x, "wait"),
      });
      const wi = new Contract(
        addressOf("WinnerIdentity"),
        abiOf("WinnerIdentity") as never,
        anonymousSigner(),
      );
      const rec = await send(wi.submitIdentityProof, [
        t!.id,
        record.credentialId,
        toUtf8Bytes(jcsCanonicalize(record)),
        proof.pA,
        proof.pB,
        proof.pC,
      ]);
      say(`identity published · ${r.firmName} · block ${rec.blockNumber}`, "ok");
      refresh();
    } catch (err) {
      say(explain(err), "no");
    } finally {
      setActing(false);
    }
  }

  // =====================================================================
  if (section === "available") {
    return (
      <>
        <div className="page-head">
          <h1>Available tenders</h1>
          <p>Tenders currently accepting sealed bids.</p>
        </div>
        <Card>
          {open.length === 0 ? (
            <Empty icon="doc" title="Nothing is open for bidding right now" />
          ) : (
            <div className="scroll-x">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Tender</th>
                    <th className="num">Minimum turnover</th>
                    <th className="num">Experience</th>
                    <th>Closes</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {open.map((x) => (
                    <tr key={x.id}>
                      <td>
                        <strong>{x.title}</strong>
                        <div className="tiny muted" style={{ marginTop: 2 }}>
                          {x.tenderIdString} · {x.buyer}
                        </div>
                      </td>
                      <td className="num">{formatBdt(x.turnoverThreshold)}</td>
                      <td className="num">{x.experienceMonths} mo</td>
                      <td>
                        <div className="small">{formatTime(x.deadline)}</div>
                        <div className="tiny muted">{formatCountdown(x.deadline, now)}</div>
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <button
                          className="btn sm primary"
                          onClick={() => {
                            onSelect(x.id);
                            goto("bidder", "submit", x.id);
                          }}
                        >
                          Bid on this
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </>
    );
  }

  // =====================================================================
  if (section === "credentials") {
    const complete =
      draft.firmName.trim().length > 1 &&
      draft.registrationNumber.trim().length > 0 &&
      draft.credentialId.trim().length > 0 &&
      draft.annualTurnover.trim().length > 0 &&
      draft.relevantExperience.trim().length > 0 &&
      draft.certificationCode.trim().length > 0;

    return (
      <>
        <div className="page-head">
          <h1>{cred.registered ? "My company" : "Register your company"}</h1>
          <p>
            Enter it once. It stays in this browser and is never sent anywhere — a bid
            proves these figures clear a tender's thresholds without revealing them.
          </p>
        </div>

        {!cred.registered ? (
          <Note tone="accent" icon="info">
            You need to register before you can bid.
          </Note>
        ) : null}

        {att ? (
          <Card
            title={`Certified by ${att.issuerLabel}`}
            sub="These figures were signed by an accredited body. You cannot alter them."
            accent="good"
            chain={
              <>
                <ChainFact k="Credential">
                  <span className="mono num">#{att.fields.credentialId.toString()}</span>
                </ChainFact>
                <ChainFact k="Valid until">
                  {formatTime(Number(att.fields.credentialValidUntil))}
                </ChainFact>
              </>
            }
          >
            <CheckList
              items={[
                {
                  label: "The body's signature verifies",
                  state: "pass",
                  value: "Verified",
                },
                {
                  label: "Issued to this firm's subject commitment",
                  state: "pass",
                  value: "Bound",
                },
                {
                  label: "Attested annual turnover",
                  state: "pass",
                  value: formatBdt(att.fields.annualTurnover),
                },
                {
                  label: "Attested experience",
                  state: "pass",
                  value: `${att.fields.relevantExperience.toString()} months`,
                },
                {
                  label: "Attested certification",
                  state: "pass",
                  value: `code ${att.fields.certificationCode.toString()}`,
                },
              ]}
            />
            <Note tone="accent" icon="info">
              <strong>This is what a bid proves.</strong> The figures above are inside the
              body's signature, so editing anything below changes nothing a tender will
              see — and the body cannot bid in your name, because your secret never left
              this browser.
            </Note>
            <button className="btn" style={{ marginTop: 14 }} onClick={removeCredential}>
              Remove this credential
            </button>
          </Card>
        ) : (
          <Card
            title="Get your figures certified"
            sub="An accredited body signs them once. Until then a bid proves only the mechanism."
          >
            <Note tone="wait" icon="alert">
              <strong>No credential from a certifying body.</strong> A bid placed now
              proves the figures you typed below, signed by this browser — which
              demonstrates the protocol but attests nothing. Ask your auditor to issue a
              credential against the commitment here.
            </Note>

            <Field
              label="Your subject commitment"
              hint="Give this to your certifying body. It reveals nothing about your secret."
            >
              <input
                className="in mono"
                readOnly
                value={myCommitment || (cred.subjectSecret ? "deriving…" : "register first")}
                onFocus={(e) => e.currentTarget.select()}
              />
            </Field>
            {myCommitment ? (
              <button
                className="btn"
                onClick={() => {
                  navigator.clipboard?.writeText(myCommitment).then(
                    () => setCommitCopied(true),
                    () => setCommitCopied(false),
                  );
                }}
              >
                <Icon name="copy" size={16} /> {commitCopied ? "Copied" : "Copy commitment"}
              </button>
            ) : null}

            <div style={{ marginTop: 20 }}>
              <Field
                label="Paste the credential your body issued"
                hint="It carries no secret, so it needs no protected channel."
              >
                <textarea
                  className="in mono"
                  rows={6}
                  placeholder='{ "format": "fairproof.credential.v1", … }'
                  value={paste}
                  onChange={(e) => setPaste(e.target.value)}
                  style={{ width: "100%", resize: "vertical" }}
                />
              </Field>
              {importErr ? (
                <Note tone="bad" icon="cross">
                  {importErr}
                </Note>
              ) : null}
              <button className="btn primary" disabled={!paste.trim()} onClick={importCredential}>
                <Icon name="seal" size={16} /> Import credential
              </button>
            </div>
          </Card>
        )}

        <Card title="Company details">
          <div className="row2">
            <Field label="Registered company name">
              <input
                className="in"
                placeholder="e.g. XYZ Construction Limited"
                value={draft.firmName}
                onChange={(e) => set("firmName", e.target.value)}
              />
            </Field>
            <Field label="Company registration number">
              <input
                className="in"
                placeholder="e.g. C-118342/2019"
                value={draft.registrationNumber}
                onChange={(e) => set("registrationNumber", e.target.value)}
              />
            </Field>
          </div>
          <Field
            label="Certificate number"
            hint="From the certifying body that assessed your firm."
          >
            <input
              className="in mono"
              placeholder="e.g. 1042"
              value={draft.credentialId}
              onChange={(e) => set("credentialId", e.target.value.replace(/\D/g, ""))}
            />
          </Field>
        </Card>

        <Card
          title={att ? "Your own copy of the figures" : "Certified figures"}
          sub={
            att
              ? "Kept for your records. The signed credential above is what a bid proves."
              : "What your certifying body has assessed. These are never published."
          }
        >
          <Field
            label="Annual turnover (BDT)"
            hint={draft.annualTurnover ? formatBdt(BigInt(draft.annualTurnover)) : "In taka."}
          >
            <input
              className="in mono"
              placeholder="e.g. 620000000"
              value={draft.annualTurnover}
              onChange={(e) => set("annualTurnover", e.target.value.replace(/\D/g, ""))}
              disabled={!!att}
            />
          </Field>
          <div className="row2">
            <Field label="Relevant experience (months)">
              <input
                className="in mono"
                placeholder="e.g. 72"
                value={draft.relevantExperience}
                onChange={(e) => set("relevantExperience", e.target.value.replace(/\D/g, ""))}
                disabled={!!att}
              />
            </Field>
            <Field label="Certification code">
              <input
                className="in mono"
                placeholder="e.g. 9001"
                value={draft.certificationCode}
                onChange={(e) => set("certificationCode", e.target.value.replace(/\D/g, ""))}
                disabled={!!att}
              />
            </Field>
          </div>
        </Card>

        <div className="row" style={{ gap: 14 }}>
          <button className="btn primary lg" disabled={!complete || !dirty} onClick={saveCompany}>
            <Icon name="check" size={17} /> {cred.registered ? "Save changes" : "Register company"}
          </button>
          {saved ? <Tag tone="good" icon="check">Saved</Tag> : null}
          {dirty && !saved ? <span className="small muted">Unsaved changes</span> : null}
          {cred.registered && !dirty ? (
            <button className="btn" onClick={() => goto("bidder", "available")}>
              Find a tender <Icon name="arrow" size={15} />
            </button>
          ) : null}
        </div>
      </>
    );
  }

  // =====================================================================
  if (section === "submit") {
    if (!t) {
      return (
        <>
          <div className="page-head">
            <h1>Submit bid</h1>
          </div>
          <Card>
            <Empty icon="bidder" title="No tender is open for bidding" />
          </Card>
        </>
      );
    }

    if (!cred.registered) {
      return (
        <>
          <div className="page-head">
            <h1>Submit bid</h1>
          </div>
          <Card>
            <Empty icon="seal" title="Register your company first">
              A bid proves your certified figures clear this tender's thresholds, so we
              need them before you can bid.
            </Empty>
            <div className="row" style={{ justifyContent: "center" }}>
              <button className="btn primary" onClick={() => goto("bidder", "credentials")}>
                Register now <Icon name="arrow" size={15} />
              </button>
            </div>
          </Card>
        </>
      );
    }

    return (
      <>
        <div className="page-head">
          <h1>Submit bid</h1>
          <p>
            Your price is encrypted before it leaves this browser. Nobody can read it
            until the deadline passes.
          </p>
        </div>

        <div className="tender-head">
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="tender-title">{t.title}</div>
            <div className="tender-meta">
              {t.tenderIdString} · closes {formatTime(t.deadline)} ·{" "}
              {formatCountdown(t.deadline, now)}
            </div>
          </div>
          <StateBadge state={t.state} />
        </div>

        <TenderPicker tenders={open} value={t?.id ?? null} onChange={onSelect} />

        {/* 1. Qualification */}
        <Card
          title="Qualification"
          sub="Checked against this tender's published requirements."
          accent={qualified ? "good" : "bad"}
        >
          <div className="spread" style={{ marginBottom: 16 }}>
            <span className="small muted">{cred.firmName || "Your company"}</span>
            {qualified ? (
              <Tag tone="good" icon="check" lg>Qualified</Tag>
            ) : (
              <Tag tone="bad" icon="cross" lg>Not qualified</Tag>
            )}
          </div>
          <CheckList
            items={clauses.map((c) => ({
              label: `${c.label} — ${c.has}`,
              state: c.ok ? "pass" : "fail",
              value: c.ok ? "Met" : `Needs ${c.needs}`,
            }))}
          />
          {!qualified ? (
            <Note tone="bad" icon="cross" >
              No proof can be produced from this credential. The circuit has no branch
              that lets an unmet requirement through, so a bid cannot be submitted at
              all — a rule enforced this way cannot be waived under pressure.{" "}
              <button className="btn sm" onClick={() => goto("bidder", "credentials")}>
                Edit my company
              </button>
            </Note>
          ) : null}
        </Card>

        {/* 2. Bid */}
        <Card title="Your bid" sub="Encrypted before it is submitted.">
          <Field label="Bid amount (BDT)" hint={formatBdt(BigInt(amount || "0"))}>
            <input
              className="in mono big"
              value={amount}
              onChange={(e) => setAmount(e.target.value.replace(/\D/g, ""))}
              disabled={busy}
            />
          </Field>

          {!t.biddingOpen ? (
            <Note tone="wait" icon="clock">
              {now < t.biddingStart ? (
                <>
                  <strong>Bidding has not opened.</strong> The tender's mandatory public
                  review window ends {formatCountdown(t.biddingStart, now)}. Nobody,
                  including the authority, can shorten it.
                </>
              ) : (
                <>
                  <strong>The deadline has passed.</strong> Bidding closed{" "}
                  {formatCountdown(t.deadline, now)} and the contract now refuses every
                  submission.
                </>
              )}
            </Note>
          ) : null}

          {quorumUp < 2 ? (
            <Note tone="bad" icon="cross">
              <strong>Secure storage is unavailable.</strong> A bid is accepted only once
              two independent stores have signed for it, so submission is blocked rather
              than degraded.
            </Note>
          ) : null}

          {download ? (
            <div style={{ marginBottom: 16 }}>
              <div className="spread" style={{ marginBottom: 6 }}>
                <span className="small">Preparing {download.what}</span>
                <span className="small muted num">{download.pct}%</span>
              </div>
              <div className="meter">
                <i style={{ width: `${download.pct}%` }} />
              </div>
            </div>
          ) : null}

          {proofDone && !submitted ? (
            <Note tone="good" icon="check">
              <strong>Zero-knowledge proof generated.</strong> It asserts that this firm
              meets every published requirement, and contains none of the figures behind
              that claim.
            </Note>
          ) : null}

          <button className="btn primary lg wide" disabled={!canSubmit} onClick={submit}>
            {busy ? (
              <>
                <span className="spin" style={{ borderTopColor: "#fff", borderColor: "rgba(255,255,255,0.4)", borderTopWidth: 2 }} />
                {phase === "proving"
                  ? "Generating proof…"
                  : phase === "sealing"
                    ? "Encrypting your price…"
                    : phase === "uploading"
                      ? "Storing securely…"
                      : "Submitting…"}
              </>
            ) : submitted ? (
              <>
                <Icon name="check" size={17} /> Bid submitted — submission #{submitted.index}
              </>
            ) : (
              <>
                <Icon name="lock" size={17} /> Submit sealed bid
              </>
            )}
          </button>

          {lines.length ? (
            <div style={{ marginTop: 16 }}>
              <Log lines={lines} />
            </div>
          ) : null}
        </Card>

        {submitted ? (
          <Card
            title="Bid accepted"
            sub="Checked against this tender's frozen rules before it was accepted."
            accent="good"
            chain={
              <>
                <ChainFact k="Transaction">
                  <Hash v={submitted.hash} lead={10} tail={6} />
                </ChainFact>
                <ChainFact k="Block">
                  <span className="mono num">{submitted.block.toLocaleString()}</span>
                </ChainFact>
                <ChainFact k="Verified">
                  <Tag tone="good" icon="check">On-chain</Tag>
                </ChainFact>
              </>
            }
          >
            <div className="spread">
              <div>
                <div className="eyebrow">Your receipt</div>
                <div style={{ fontSize: 18, fontWeight: 650, marginTop: 5 }}>
                  Submission #{submitted.index}
                </div>
                <div className="small muted" style={{ marginTop: 4 }}>
                  Submitted from a new address with no balance, so nothing links this bid
                  to your company.
                </div>
              </div>
              <button className="btn" onClick={() => goto("bidder", "mybids", t.id)}>
                Track it <Icon name="arrow" size={15} />
              </button>
            </div>
          </Card>
        ) : null}

        <Privacy
          learns={[
            "That an approved issuer attested figures meeting every threshold",
            "A one-time marker, so the same credential cannot bid twice",
            "A commitment to a price nobody can read",
          ]}
          never={[
            `Your turnover — only that it clears ${formatBdt(t.turnoverThreshold)}`,
            "Your experience, certification or company name",
            "Your price, until the committee opens it after the deadline",
          ]}
        />
      </>
    );
  }

  // =====================================================================
  // My bids
  if (!t) {
    return (
      <>
        <div className="page-head">
          <h1>My bids</h1>
        </div>
        <Card>
          <Empty icon="verification" title="No tenders on this deployment" />
        </Card>
      </>
    );
  }

  return (
    <>
      <div className="page-head">
        <h1>My bids</h1>
        <p>
          Nothing on the chain says a bid is yours, so this is matched from your own copy.
        </p>
      </div>

      <TenderPicker tenders={tenders} value={t?.id ?? null} onChange={onSelect} />

      {receipts.length === 0 ? (
        <Card>
          <Empty icon="bidder" title="No bids on this tender from this browser">
            Place one from Submit bid.
          </Empty>
        </Card>
      ) : (
        receipts.map((r) => {
          const bid = t.bids[r.submissionIndex];
          const mine = bid && bid.bidCommitment.toString() === r.bidCommitment;
          const won = t.award && t.award.winnerCommitment.toString() === r.bidCommitment;
          const lost = t.award && !won;
          return (
            <Card
              key={r.nullifier}
              title={`Submission #${r.submissionIndex}`}
              sub={`${r.firmName} · ${formatBdt(BigInt(r.amountMinorUnit))} · ${formatTime(r.submittedAt)}`}
              accent={won ? "good" : lost ? "neutral" : "accent"}
              chain={
                <>
                  <ChainFact k="Transaction">
                    <Hash v={r.txHash} lead={10} tail={6} />
                  </ChainFact>
                  <ChainFact k="Reference">
                    <span className="mono">{shortHash(r.nullifier, 8, 6)}</span>
                  </ChainFact>
                  <ChainFact k="Verified">
                    <Tag tone={mine ? "good" : "bad"} icon={mine ? "check" : "cross"}>
                      {mine ? "On-chain" : "Mismatch"}
                    </Tag>
                  </ChainFact>
                </>
              }
              right={
                won ? (
                  <Tag tone="good" icon="check" lg>Won</Tag>
                ) : lost ? (
                  <Tag icon="dash" lg>Not selected</Tag>
                ) : bid?.openable ? (
                  <Tag tone="wait" icon="committee" lg>Opened</Tag>
                ) : (
                  <Tag tone="accent" icon="lock" lg>Sealed</Tag>
                )
              }
            >
              <CheckList
                items={[
                  { label: "Bid recorded on the chain", state: mine ? "pass" : "pending" },
                  { label: "Bidding closed, set final", state: t.biddingOpen ? "pending" : "pass",
                    value: t.biddingOpen ? formatCountdown(t.deadline, now) : `${t.submissionCount} bids` },
                  { label: "Opened by the committee", state: bid?.openable ? "pass" : "pending",
                    value: bid ? `${bid.shares} of ${bid.threshold} shares` : "—" },
                  { label: "Credential valid at the deadline", state: bid?.statusProven ? "pass" : "pending" },
                  {
                    label: "Result",
                    state: won ? "pass" : lost ? "fail" : "pending",
                    value: won
                      ? t.award!.winningPrice > 0n
                        ? formatBdt(t.award!.winningPrice)
                        : "Won"
                      : lost
                        ? `Submission #${t.award!.winnerSubmissionIndex} won`
                        : "Awaiting award",
                  },
                ]}
              />
              {/* Two things only this bidder can do. */}
              {mine && !t.biddingOpen && t.state >= 3 && !bid?.statusProven ? (
                <Note tone="accent" icon="alert">
                  <strong>Confirm you were still eligible at the deadline.</strong> The
                  award cannot be recorded until you do — the contract refuses it — and
                  nobody can do it for you, because the proof needs your secret.
                  <div style={{ marginTop: 12 }}>
                    <button
                      className="btn primary"
                      disabled={busy || !r.subjectSecret}
                      onClick={() => confirmStatus(r)}
                    >
                      Confirm eligibility
                    </button>
                  </div>
                </Note>
              ) : null}

              {won && !t.identity ? (
                <Note tone="good" icon="check">
                  <strong>You won. Publish your identity to complete the record.</strong>{" "}
                  The proof shows you placed the winning bid; until it is published nobody
                  is named at all.
                  <div style={{ marginTop: 12 }}>
                    <button
                      className="btn primary"
                      disabled={busy || !r.subjectSecret}
                      onClick={() => publishIdentity(r)}
                    >
                      Publish identity
                    </button>
                  </div>
                </Note>
              ) : null}

              {lost ? (
                <Note icon="info">
                  The chain does not publish losing prices, so nobody learns what you bid
                  from this result. You know it only because you placed it.
                </Note>
              ) : null}
            </Card>
          );
        })
      )}

      {lines.length ? (
        <Card title="Activity">
          <Log lines={lines} />
        </Card>
      ) : null}
    </>
  );
}
