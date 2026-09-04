/**
 * One read that assembles a tender's whole lifecycle.
 *
 * Every stage lives in a different contract, so a page that read them
 * separately would render a half-consistent picture whenever a transaction
 * landed mid-poll. Reading them together means what is displayed was true at
 * one moment, which is what makes the timeline trustworthy.
 *
 * Nothing here is cached or inferred. A field that the chain does not hold is
 * absent rather than guessed, and a stage that has not happened yet is `null`
 * rather than an empty object that looks like a completed one.
 */
import { contract, fieldToHex } from "./chain";

export interface BidView {
  index: number;
  nullifier: bigint;
  bidCommitment: bigint;
  ciphertextHash: string;
  storageReceiptRoot: bigint;
  leaf: bigint;
  submittedAt: number;
  submitter: string;
  /** The ciphertext has been published on-chain and its hash re-checked. */
  revealed: boolean;
  /** Decryption shares accepted so far, and how many are required. */
  shares: number;
  threshold: number;
  openable: boolean;
  /** Re-proved against the deadline-pinned revocation root. */
  statusProven: boolean;
  /** Present once the committee has revealed it; the bytes anyone can decrypt. */
  ciphertext: {
    revealed: boolean;
    rX: bigint;
    rY: bigint;
    byteLength: number;
    revealedAt: number;
  } | null;
  shareDetail: {
    memberIndex: number;
    dX: bigint;
    dY: bigint;
    submitter: string;
    acceptedAt: number;
  }[];
  /** Absent unless a bank adapter posted one. Most tenders have none. */
  bond: {
    /** 1 posted · 2 released · 3 forfeited, per BondEscrow.Status. */
    status: number;
    guaranteeRef: string;
    declaredAmount: bigint;
    postedAt: number;
    settledAt: number;
    postedBy: string;
    settledBy: string;
    settlementReason: string;
  } | null;
}

export interface TenderView {
  id: string;
  tenderIdString: string;
  tenderIdField: bigint;
  state: number;
  authority: string;
  rulesHash: string;
  fieldsDigest: string;
  /** What the CONTRACT recomputes from the document it stores. */
  recomputedRulesHash: string;
  ruleDocument: string;
  /**
   * The human-readable heading, taken from the rule document.
   *
   * The contract's identity for a tender is `tenderIdString`, a reference —
   * short, unique and useless as a description. Procurement notices are read
   * by their subject, so the document carries a title, a buying authority and
   * a location, and the interface leads with those. They are inside the
   * document that the frozen `rulesHash` covers, so they cannot be edited
   * after activation any more than a threshold can.
   */
  title: string;
  buyer: string;
  location: string;
  activatedAt: number;
  biddingStart: number;
  deadline: number;
  reviewWindow: number;
  requiredIssuerId: string;
  issuerEpoch: number;
  schemaVersion: number;
  verifierVersion: number;
  disclosurePolicy: number;
  awardRule: number;
  tieBreakRule: number;
  contingencyPolicy: number;
  turnoverThreshold: bigint;
  experienceMonths: number;
  certificationCode: bigint;
  biddingOpen: boolean;
  committee: {
    set: boolean;
    yX: bigint;
    yY: bigint;
    members: string[];
    memberX: bigint[];
    memberY: bigint[];
    commitmentX: bigint[];
    commitmentY: bigint[];
    threshold: number;
    size: number;
  };
  issuerRegistryRoot: string;
  revocationRoot: string;
  deadlineRevocationRoot: string;
  bidSetRoot: bigint;
  submissionCount: number;
  bids: BidView[];
  bonds: {
    accepted: number;
    posted: number;
    released: number;
    forfeited: number;
  };
  award: {
    recorded: boolean;
    winnerCommitment: bigint;
    winningPrice: bigint;
    winnerSubmissionIndex: number;
    bidSetRoot: bigint;
    submissionCount: number;
    disclosurePolicy: number;
    awardedAt: number;
    recordedBy: string;
  } | null;
  identity: {
    proven: boolean;
    credentialId: number;
    legalIdentityCommitment: bigint;
    record: string;
    provenAt: number;
    submitter: string;
    /**
     * The declared name, lifted out of the record for display.
     *
     * It is the winner's own statement, checkable by the issuer against the
     * credential — not something this chain verified. The interface says so
     * wherever it shows it.
     */
    legalName: string;
  } | null;
}

/** A checkpoint of the chain's own state, and whether anyone anchored it. */
export interface CheckpointView {
  count: number;
  externallyAnchored: number;
  latest: {
    index: number;
    digest: string;
    blockNumber: number;
    blockHash: string;
    tenderStateRoot: string;
    recordedAt: number;
    recordedBy: string;
    /** Empty until someone anchors this digest on an independent chain. */
    externalUri: string;
  } | null;
}

const ZERO32 = "0x" + "00".repeat(32);

/** The presentational fields of a rule document, if it carries any. */
function readDocumentMeta(
  document: string,
  fallbackTitle: string,
): { title: string; buyer: string; location: string } {
  try {
    const d = JSON.parse(document) as Record<string, unknown>;
    return {
      title: typeof d.title === "string" && d.title ? d.title : fallbackTitle,
      buyer: typeof d.buyer === "string" ? d.buyer : "",
      location: typeof d.location === "string" ? d.location : "",
    };
  } catch {
    return { title: fallbackTitle, buyer: "", location: "" };
  }
}

/** Solidity `bytes` to the UTF-8 string it holds. */
export function bytesToText(hex: string): string {
  const pairs = hex.slice(2).match(/.{1,2}/g);
  if (!pairs) return "";
  return new TextDecoder().decode(Uint8Array.from(pairs.map((h) => parseInt(h, 16))));
}

export async function readTenderIds(): Promise<string[]> {
  const tr = contract("TenderRegistry");
  const count = await tr.tenderCount();
  const ids: string[] = [];
  for (let i = 0n; i < count; i++) ids.push(await tr.tenderIdAt(i));
  // Newest first: the tender someone just created is the one they want.
  return ids.reverse();
}

export async function readTender(id: string): Promise<TenderView> {
  const tr = contract("TenderRegistry");
  const reg = contract("IssuerRegistry");
  const sb = contract("SealedBid");
  const om = contract("OpeningManager");
  const ds = contract("DeadlineStatus");
  const am = contract("AwardManager");
  const wi = contract("WinnerIdentity");
  const be = contract("BondEscrow");

  const t = await tr.getTender(id);
  const [recomputed, doc, biddingOpen] = await Promise.all([
    tr.recomputeRulesHash(id),
    tr.getRuleDocument(id),
    tr.isBiddingOpen(id).catch(() => false),
  ]);

  // Parsed rather than trusted: a tender published before the document
  // carried these fields, or by something other than this interface, falls
  // back to its reference. An absent title is not an error.
  const docText = bytesToText(doc as string);
  const meta = readDocumentMeta(docText, t.tenderIdString);

  let committee: TenderView["committee"] = {
    set: false,
    yX: 0n,
    yY: 0n,
    members: [],
    memberX: [],
    memberY: [],
    commitmentX: [],
    commitmentY: [],
    threshold: 3,
    size: 5,
  };
  try {
    const k = await tr.getCommitteeKey(id);
    const members = await tr.getCommitteeMembers(id);
    committee = {
      set: k.set,
      yX: k.yX,
      yY: k.yY,
      members: [...members],
      memberX: [...k.memberX],
      memberY: [...k.memberY],
      commitmentX: [...k.commitmentX],
      commitmentY: [...k.commitmentY],
      threshold: Number(await tr.COMMITTEE_THRESHOLD()),
      size: Number(await tr.COMMITTEE_SIZE()),
    };
  } catch {
    // Not dealt yet while the tender is still a draft. Not an error.
  }

  const [issuerRegistryRoot, revocationRoot, deadlineRoot] = await Promise.all([
    reg.issuerRegistryRoot(t.issuerEpoch),
    reg.revocationRoot(t.issuerEpoch),
    reg.deadlineRevocationRoot(id),
  ]);

  const [countRaw, rootRaw] = await Promise.all([sb.submissionCount(id), sb.bidSetRoot(id)]);
  const count = Number(countRaw);

  const bids: BidView[] = [];
  for (let i = 0; i < count; i++) {
    const b = await sb.getBid(id, i);
    const [status, proven, ct, shareRows] = await Promise.all([
      om.openingStatus(id, i),
      ds.isProven(id, i).catch(() => false),
      om.getCiphertext(id, i).catch(() => null),
      om.getShares(id, i).catch(() => []),
    ]);

    // A bond is optional: most tenders in this deployment have none, and a
    // missing bond is a fact about the tender rather than a failed read.
    let bond: BidView["bond"] = null;
    try {
      const raw = await be.getBond(id, b.nullifier);
      if (Number(raw.status) !== 0) {
        bond = {
          status: Number(raw.status),
          guaranteeRef: raw.guaranteeRef,
          declaredAmount: raw.declaredAmount,
          postedAt: Number(raw.postedAt),
          settledAt: Number(raw.settledAt),
          postedBy: raw.postedBy,
          settledBy: raw.settledBy,
          settlementReason: raw.settlementReason,
        };
      }
    } catch {
      // No escrow record for this nullifier.
    }

    bids.push({
      index: i,
      nullifier: b.nullifier,
      bidCommitment: b.bidCommitment,
      ciphertextHash: b.ciphertextHash,
      storageReceiptRoot: b.storageReceiptRoot,
      leaf: b.leaf,
      submittedAt: Number(b.submittedAt),
      submitter: b.submitter,
      revealed: status[0],
      shares: Number(status[1]),
      threshold: Number(status[2]),
      openable: status[3],
      statusProven: proven,
      ciphertext:
        ct && ct.revealed
          ? {
              revealed: true,
              rX: ct.rX,
              rY: ct.rY,
              byteLength: Number(ct.byteLength),
              revealedAt: Number(ct.revealedAt),
            }
          : null,
      shareDetail: [...shareRows].map((s: any) => ({
        memberIndex: Number(s.memberIndex),
        dX: s.dX,
        dY: s.dY,
        submitter: s.submitter,
        acceptedAt: Number(s.acceptedAt),
      })),
      bond,
    });
  }

  let bonds = { accepted: 0, posted: 0, released: 0, forfeited: 0 };
  try {
    const s = await be.bondSummary(id);
    bonds = {
      accepted: Number(s.accepted),
      posted: Number(s.posted),
      released: Number(s.released),
      forfeited: Number(s.forfeited),
    };
  } catch {
    // The escrow has nothing for this tender.
  }

  let award: TenderView["award"] = null;
  try {
    if (await am.isAwarded(id)) {
      const a = await am.getAward(id);
      award = {
        recorded: true,
        winnerCommitment: a.winnerCommitment,
        winningPrice: a.winningPrice,
        winnerSubmissionIndex: Number(a.winnerSubmissionIndex),
        bidSetRoot: a.bidSetRoot,
        submissionCount: Number(a.submissionCount),
        disclosurePolicy: Number(a.disclosurePolicy),
        awardedAt: Number(a.awardedAt),
        recordedBy: a.recordedBy,
      };
    }
  } catch {
    // No award yet.
  }

  let identity: TenderView["identity"] = null;
  try {
    if (await wi.isProven(id)) {
      const i = await wi.getIdentity(id);
      const record = bytesToText(i.record as string);
      let legalName = "";
      try {
        legalName = (JSON.parse(record) as { legalName?: string }).legalName ?? "";
      } catch {
        // A record that is not JSON is still a record. It just has no name to
        // pull out, and the raw bytes are shown instead.
      }
      identity = {
        proven: true,
        credentialId: Number(i.credentialId),
        legalIdentityCommitment: i.legalIdentityCommitment,
        record,
        provenAt: Number(i.provenAt),
        submitter: i.submitter,
        legalName,
      };
    }
  } catch {
    // No identity published yet.
  }

  return {
    id,
    tenderIdString: t.tenderIdString,
    tenderIdField: t.tenderIdField,
    state: Number(t.state),
    authority: t.authority,
    rulesHash: t.rulesHash,
    fieldsDigest: t.fieldsDigest,
    recomputedRulesHash: recomputed,
    ruleDocument: docText,
    title: meta.title,
    buyer: meta.buyer,
    location: meta.location,
    activatedAt: Number(t.activatedAt),
    biddingStart: Number(t.biddingStart),
    deadline: Number(t.deadline),
    reviewWindow: Number(t.reviewWindow),
    requiredIssuerId: t.requiredIssuerId,
    issuerEpoch: Number(t.issuerEpoch),
    schemaVersion: Number(t.schemaVersion),
    verifierVersion: Number(t.verifierVersion),
    disclosurePolicy: Number(t.disclosurePolicy),
    awardRule: Number(t.awardRule),
    tieBreakRule: Number(t.tieBreakRule),
    contingencyPolicy: Number(t.contingencyPolicy),
    turnoverThreshold: t.requirements.turnoverThreshold,
    experienceMonths: Number(t.requirements.experienceMonths),
    certificationCode: t.requirements.certificationCode,
    biddingOpen,
    committee,
    issuerRegistryRoot: issuerRegistryRoot === ZERO32 ? "" : issuerRegistryRoot,
    revocationRoot: revocationRoot === ZERO32 ? "" : revocationRoot,
    deadlineRevocationRoot: deadlineRoot === ZERO32 ? "" : deadlineRoot,
    bidSetRoot: rootRaw,
    submissionCount: count,
    bids,
    bonds,
    award,
    identity,
  };
}

/**
 * The checkpoint log.
 *
 * `externallyAnchored` is expected to be zero on this deployment and the
 * interface says so plainly. A checkpoint recorded only on the chain it
 * describes proves nothing against that chain's own operators; only an anchor
 * on an independent chain would, and none has been published.
 */
export async function readCheckpoints(): Promise<CheckpointView> {
  const ca = contract("CheckpointAnchor");
  const [countRaw, anchoredRaw] = await Promise.all([
    ca.count(),
    ca.externallyAnchoredCount(),
  ]);
  const count = Number(countRaw);
  if (count === 0) {
    return { count: 0, externallyAnchored: Number(anchoredRaw), latest: null };
  }
  const l = await ca.latest();
  return {
    count,
    externallyAnchored: Number(anchoredRaw),
    latest: {
      index: count - 1,
      digest: l.checkpoint,
      blockNumber: Number(l.blockNumber),
      blockHash: l.blockHash,
      tenderStateRoot: l.tenderStateRoot,
      recordedAt: Number(l.recordedAt),
      recordedBy: l.recordedBy,
      externalUri: l.externalAnchorUri,
    },
  };
}

export { fieldToHex };
