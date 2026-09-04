/**
 * Award witness construction. Whitepaper Section 7, plan Section 14.
 *
 * THE PROVER IS THE AUTHORITY, not a bidder. After the opening ceremony the
 * authority is the only party holding every opened bid, and it holds only
 * `bidAmount` and `bidNonce` per bid - never any `subjectSecret`. So this
 * module runs on the authority's machine and there is no privacy cost to it
 * doing so.
 *
 * The witness is a padded 32-slot vector, because the circuit is fixed-size.
 * Inactive slots carry the padding leaf, and every value in them is set to
 * zero rather than left undefined: an unconstrained witness value is one an
 * attacker gets to choose.
 */
import {
  BID_TREE_DEPTH,
  DOMAIN_PADDING_V1,
  MAX_BIDS,
} from "./domains.js";
import { toLimbs } from "./field.js";
import { IncrementalMerkleTree } from "./merkle.js";
import { bidCommitment, bidLeaf } from "./poseidon.js";

/** Disclosure policy codes. Must match TenderRegistry and the circuit. */
export const DISCLOSE_WINNING_PRICE = 1;
export const CONCEAL_WINNING_PRICE = 2;

/** One opened bid, as the authority holds it after the ceremony. */
export interface OpenedBid {
  submissionIndex: number;
  nullifier: bigint;
  bidAmount: bigint;
  bidNonce: bigint;
  ciphertextHashField: bigint;
}

export interface AwardWitness {
  // public
  tenderIdField: bigint;
  rulesHashHi: bigint;
  rulesHashLo: bigint;
  bidSetRoot: bigint;
  submissionCount: bigint;
  winnerCommitment: bigint;
  winningPrice: bigint;
  disclosurePolicy: bigint;
  // private
  nullifier: bigint[];
  bidAmount: bigint[];
  bidNonce: bigint[];
  ciphertextHashField: bigint[];
  winnerIndex: bigint;
}

/**
 * Choose the winner: lowest amount, earliest submission index on a tie.
 *
 * The tie-break is the finalized submission sequence, which sits inside the
 * validator-ordering trust boundary - a tie is resolved by consensus ordering
 * rather than by anything the authority picks. That has to be documented
 * wherever the rule is stated (plan Section 14.1).
 */
export function selectWinner(bids: OpenedBid[]): OpenedBid {
  if (bids.length === 0) {
    throw new Error("selectWinner: no accepted bids, so there is no winner");
  }
  return bids.reduce((best, b) => {
    if (b.bidAmount < best.bidAmount) return b;
    if (b.bidAmount === best.bidAmount && b.submissionIndex < best.submissionIndex) return b;
    return best;
  });
}

/**
 * Assemble the award witness.
 *
 * The bid-set root is recomputed here from the leaves, and the caller is
 * expected to compare it against the root the chain holds. The circuit
 * recomputes it a third time from the padded slots. Three independent
 * computations of one value is what makes "the bid set is complete" a
 * checkable statement rather than an assertion.
 */
export function buildAwardWitness(params: {
  bids: OpenedBid[];
  tenderIdField: bigint;
  rulesHash: string;
  disclosurePolicy: number;
  /** Override the winner, for negative tests only. */
  winnerIndexOverride?: number;
}): AwardWitness {
  const { bids, tenderIdField, rulesHash, disclosurePolicy } = params;

  if (bids.length > MAX_BIDS) {
    throw new Error(
      `buildAwardWitness: ${bids.length} bids exceeds MAX_BIDS ${MAX_BIDS}. ` +
        `Whitepaper Section 7 requires the 33rd bid be rejected at acceptance, ` +
        `so this state should be unreachable.`,
    );
  }
  if (disclosurePolicy !== DISCLOSE_WINNING_PRICE && disclosurePolicy !== CONCEAL_WINNING_PRICE) {
    throw new Error(
      `buildAwardWitness: unsupported disclosurePolicy ${disclosurePolicy}. ` +
        `The circuit rejects anything but 1 or 2 so a new policy cannot ` +
        `silently fall through to "publish".`,
    );
  }

  // Slots must be in submission order, since the leaf commits to the index.
  const ordered = [...bids].sort((a, b) => a.submissionIndex - b.submissionIndex);
  ordered.forEach((b, i) => {
    if (b.submissionIndex !== i) {
      throw new Error(
        `buildAwardWitness: submission indices must be 0..n-1 with no gaps; ` +
          `slot ${i} carries index ${b.submissionIndex}`,
      );
    }
  });

  const nullifier: bigint[] = [];
  const bidAmount: bigint[] = [];
  const bidNonce: bigint[] = [];
  const ciphertextHashField: bigint[] = [];
  const leaves: bigint[] = [];

  for (let i = 0; i < MAX_BIDS; i++) {
    const b = ordered[i];
    if (b) {
      nullifier.push(b.nullifier);
      bidAmount.push(b.bidAmount);
      bidNonce.push(b.bidNonce);
      ciphertextHashField.push(b.ciphertextHashField);
      leaves.push(
        bidLeaf({
          nullifier: b.nullifier,
          bidCommitment: bidCommitment({
            bidAmount: b.bidAmount,
            bidNonce: b.bidNonce,
            tenderIdField,
            nullifier: b.nullifier,
          }),
          ciphertextHashField: b.ciphertextHashField,
          submissionIndex: i,
        }),
      );
    } else {
      // Zeroed, not left undefined. An unconstrained witness value is one an
      // attacker gets to choose.
      nullifier.push(0n);
      bidAmount.push(0n);
      bidNonce.push(0n);
      ciphertextHashField.push(0n);
      leaves.push(DOMAIN_PADDING_V1);
    }
  }

  const tree = new IncrementalMerkleTree(BID_TREE_DEPTH);
  for (const leaf of leaves) tree.insert(leaf);

  const winnerIndex =
    params.winnerIndexOverride ?? selectWinner(ordered).submissionIndex;
  const winner = ordered[winnerIndex];
  if (!winner) {
    throw new Error(`buildAwardWitness: slot ${winnerIndex} is not an active bid`);
  }

  const winnerCommitment = bidCommitment({
    bidAmount: winner.bidAmount,
    bidNonce: winner.bidNonce,
    tenderIdField,
    nullifier: winner.nullifier,
  });
  const { hi, lo } = toLimbs(rulesHash);

  return {
    tenderIdField,
    rulesHashHi: hi,
    rulesHashLo: lo,
    bidSetRoot: tree.root(),
    submissionCount: BigInt(ordered.length),
    winnerCommitment,
    // Zero when the policy conceals it. The circuit constrains this, so a
    // prover cannot publish the price under a winner-only policy.
    winningPrice:
      disclosurePolicy === DISCLOSE_WINNING_PRICE ? winner.bidAmount : 0n,
    disclosurePolicy: BigInt(disclosurePolicy),
    nullifier,
    bidAmount,
    bidNonce,
    ciphertextHashField,
    winnerIndex: BigInt(winnerIndex),
  };
}

/** The circuit input object, all values as decimal strings. */
export function awardCircuitInput(w: AwardWitness): Record<string, string | string[]> {
  const s = (v: bigint) => v.toString();
  const arr = (a: bigint[]) => a.map(s);
  return {
    tenderIdField: s(w.tenderIdField),
    rulesHashHi: s(w.rulesHashHi),
    rulesHashLo: s(w.rulesHashLo),
    bidSetRoot: s(w.bidSetRoot),
    submissionCount: s(w.submissionCount),
    winnerCommitment: s(w.winnerCommitment),
    winningPrice: s(w.winningPrice),
    disclosurePolicy: s(w.disclosurePolicy),
    nullifier: arr(w.nullifier),
    bidAmount: arr(w.bidAmount),
    bidNonce: arr(w.bidNonce),
    ciphertextHashField: arr(w.ciphertextHashField),
    winnerIndex: s(w.winnerIndex),
  };
}

/** Public signals in the frozen order. Spec Section 17. */
export function awardPublicSignals(w: AwardWitness): bigint[] {
  return [
    w.tenderIdField,
    w.rulesHashHi,
    w.rulesHashLo,
    w.bidSetRoot,
    w.submissionCount,
    w.winnerCommitment,
    w.winningPrice,
    w.disclosurePolicy,
  ];
}
