/**
 * What a bidder keeps after submitting.
 *
 * The chain records a nullifier and a commitment, and deliberately nothing
 * that ties either to a firm — which is the point of the protocol and also the
 * reason a bidder cannot come back later and ask "which of these is mine?".
 * Only the bidder can answer that, from their own copy.
 *
 * So this is that copy: the values the browser generated at submission time,
 * held in this browser's storage and never transmitted. A real bidding firm
 * keeps exactly this, in a file or a safe, for exactly the same reason — it is
 * the only thing that lets them prove later which bid was theirs.
 *
 * Losing it is not a disaster: the bid stays on-chain, valid and openable by
 * the committee. What is lost is the bidder's ability to point at it.
 */
const KEY = "fairproof.receipts.v1";

export interface BidReceipt {
  tenderId: string;
  tenderIdString: string;
  tenderTitle: string;
  /** The firm this bid was placed for, from the profile that was loaded. */
  firmName: string;
  submissionIndex: number;
  /** Decimal strings: these are field elements, not JavaScript numbers. */
  nullifier: string;
  bidCommitment: string;
  ciphertextHash: string;
  /** The bidder's own copy of what it bid, so it can check the opening. */
  amountMinorUnit: string;
  bidNonce: string;
  /**
   * The secret behind this bid, and the credential it was proved from.
   *
   * Kept because two later steps need them and NOBODY else can supply them:
   * re-proving that the credential was still valid at the deadline, and — if
   * this bid wins — proving ownership of it before a name is published. An
   * authority cannot do either on a bidder's behalf, which is the point.
   */
  subjectSecret?: string;
  /**
   * The body-issued credential this bid was proved from, verbatim.
   *
   * Kept for the same reason as the secret: the close-time re-proof and the
   * ownership proof must assert the SAME signed figures, or they describe a
   * different credential and the chain rejects them. Absent for a
   * self-declared bid.
   */
  attestation?: string;
  credential?: {
    credentialId: string;
    annualTurnover: string;
    relevantExperience: string;
    certificationCode: string;
    validForDays: number;
    registrationNumber?: string;
  };
  txHash: string;
  from: string;
  gasUsed: string;
  submittedAt: number;
  /**
   * True when this receipt was served as a file rather than kept by this
   * browser — see `loadSeededReceipts`. The panel says so, because a receipt
   * is private material and three of them at one URL is not.
   */
  seeded?: boolean;
}

type Store = Record<string, BidReceipt>;

/** One entry per submission, keyed so a re-submission cannot silently shadow. */
const idOf = (r: Pick<BidReceipt, "tenderId" | "nullifier">) => `${r.tenderId}:${r.nullifier}`;

function read(): Store {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Store) : {};
  } catch {
    // Storage disabled, private mode, or corrupt. An empty set is correct: the
    // bidder simply cannot point at their bid, which is visible on screen.
    return {};
  }
}

function write(s: Store): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(s));
  } catch {
    // Nothing to do but let the caller find no receipt later.
  }
}

export function saveReceipt(r: BidReceipt): void {
  const s = read();
  s[idOf(r)] = r;
  write(s);
}

export function receiptsFor(tenderId: string): BidReceipt[] {
  return Object.values(read())
    .filter((r) => r.tenderId === tenderId)
    .sort((a, b) => a.submissionIndex - b.submissionIndex);
}

export function allReceipts(): BidReceipt[] {
  return Object.values(read()).sort((a, b) => b.submittedAt - a.submittedAt);
}

/**
 * Receipts served as files, for a tender completed by `npm run tender:complete`.
 *
 * A bid placed from this workspace leaves its receipt in this browser, which is
 * what a real bidding firm does — and it means a reader who did not place the
 * bids sees nothing afterwards. A seeded tender therefore ships all three
 * firms' receipts so the outcome is inspectable.
 *
 * That is a real difference and the panel states it: one firm holds only its
 * own receipt, and seeing three at once is a property of the seed rather than
 * of the protocol.
 */
export async function loadSeededReceipts(): Promise<BidReceipt[]> {
  try {
    const res = await fetch("/bidder-receipts/index.json");
    if (!res.ok) return [];
    const { receipts } = (await res.json()) as { receipts?: BidReceipt[] };
    return (receipts ?? []).map((r) => ({ ...r, seeded: true }));
  } catch {
    // No seeded receipts on this deployment. Not an error.
    return [];
  }
}

export function forgetReceipt(tenderId: string, nullifier: string): void {
  const s = read();
  delete s[idOf({ tenderId, nullifier })];
  write(s);
}
