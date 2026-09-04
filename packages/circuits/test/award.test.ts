import { beforeAll, describe, expect, it } from "vitest";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// @ts-expect-error - circom_tester ships no types
import { wasm as wasmTester } from "circom_tester";
import {
  CONCEAL_WINNING_PRICE,
  DISCLOSE_WINNING_PRICE,
  DOMAIN_PADDING_V1,
  MAX_BIDS,
  awardCircuitInput,
  bidCommitment,
  buildAwardWitness,
  initPoseidon,
  selectWinner,
  tenderIdField,
  type AwardWitness,
  type OpenedBid,
} from "@fairproof/crypto";

/**
 * The award circuit: whitepaper Section 7, development plan Sections 14.2
 * and 14.3.
 *
 * Section 14.3 lists eight attacks that must all fail. Each has a test here,
 * named after the attack rather than after the mechanism, because what a
 * reviewer wants to know is "can the authority drop the cheapest bid?" and
 * not "is constraint 3 satisfied".
 *
 * A negative test that unexpectedly PASSES is a build-stopping defect (plan
 * Section 24.9): it means the circuit is unsound, silently.
 */

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(here, "..");

const TENDER = "FP-00014";
const RULES_HASH = "0x7d86c9f337789b3b6b5e1e6b6f5df7fb123b0634a8cee87cb4ad3a9941eae6e6";

let circuit: any;
let tf: bigint;

beforeAll(async () => {
  await initPoseidon();
  circuit = await wasmTester(join(pkgRoot, "src/award.circom"), {
    include: [join(pkgRoot, "../../node_modules")],
  });
  tf = tenderIdField(TENDER);
}, 600000);

/** Five accepted bids; slot 2 is the cheapest, so slot 2 must win. */
function bids(): OpenedBid[] {
  const amounts = [8150000n, 7900000n, 7400000n, 8900000n, 8050000n];
  return amounts.map((bidAmount, i) => ({
    submissionIndex: i,
    nullifier: 1000n + BigInt(i) * 7777n,
    bidAmount,
    bidNonce: 500000n + BigInt(i) * 31n,
    ciphertextHashField: 90000n + BigInt(i) * 13n,
  }));
}

function witness(overrides: Partial<Parameters<typeof buildAwardWitness>[0]> = {}) {
  return buildAwardWitness({
    bids: bids(),
    tenderIdField: tf,
    rulesHash: RULES_HASH,
    disclosurePolicy: DISCLOSE_WINNING_PRICE,
    ...overrides,
  });
}

/** Run the circuit, expecting success. */
async function accepts(w: AwardWitness) {
  const wtns = await circuit.calculateWitness(awardCircuitInput(w), true);
  await circuit.checkConstraints(wtns);
  return wtns;
}

/** Run the circuit, expecting the constraints to fail. */
async function rejects(w: AwardWitness, label: string) {
  await expect(
    (async () => {
      const wtns = await circuit.calculateWitness(awardCircuitInput(w), true);
      await circuit.checkConstraints(wtns);
    })(),
    label,
  ).rejects.toThrow();
}

describe("the honest award", () => {
  it("accepts the lowest-priced bid over the complete set", async () => {
    const w = witness();
    expect(w.submissionCount).toBe(5n);
    expect(w.winnerIndex).toBe(2n);
    expect(w.winningPrice).toBe(7400000n);
    await accepts(w);
  });

  it("the winner commitment is the cheapest bid's", async () => {
    const w = witness();
    const cheapest = bids()[2];
    expect(w.winnerCommitment).toBe(
      bidCommitment({
        bidAmount: cheapest.bidAmount,
        bidNonce: cheapest.bidNonce,
        tenderIdField: tf,
        nullifier: cheapest.nullifier,
      }),
    );
  });

  it("works at 1, 5, 10, 25 and 32 bids in the SAME padded circuit", async () => {
    // Whitepaper Section 19.3 promises timings "at 5 / 10 / 25 accepted bids
    // in the same padded circuit", so the padding has to be exercised at
    // several counts, not only the demo's five.
    for (const n of [1, 5, 10, 25, MAX_BIDS]) {
      const set: OpenedBid[] = Array.from({ length: n }, (_, i) => ({
        submissionIndex: i,
        // Descending amounts, so the LAST slot wins - which also checks the
        // minimum search does not just happen to pick slot 0.
        bidAmount: 9000000n - BigInt(i) * 1000n,
        nullifier: 7n + BigInt(i) * 99991n,
        bidNonce: 3n + BigInt(i) * 7n,
        ciphertextHashField: 11n + BigInt(i) * 5n,
      }));
      const w = buildAwardWitness({
        bids: set,
        tenderIdField: tf,
        rulesHash: RULES_HASH,
        disclosurePolicy: DISCLOSE_WINNING_PRICE,
      });
      expect(w.winnerIndex, `n=${n}`).toBe(BigInt(n - 1));
      await accepts(w);
    }
  }, 600000);

  it("padding slots use DOMAIN_PADDING_V1, not zero", () => {
    // A zero leaf is indistinguishable from an empty subtree, which would let
    // a real leaf be swapped for an apparently-empty slot without changing
    // the root.
    expect(DOMAIN_PADDING_V1).not.toBe(0n);
    const w = witness();
    // Inactive slots carry zeroed witness values.
    expect(w.nullifier[5]).toBe(0n);
    expect(w.bidAmount[5]).toBe(0n);
  });
});

describe("disclosure policy governs the published price", () => {
  it("publishes the winning price under policy 1", async () => {
    const w = witness({ disclosurePolicy: DISCLOSE_WINNING_PRICE });
    expect(w.winningPrice).toBe(7400000n);
    await accepts(w);
  });

  it("publishes ZERO under a winner-only policy", async () => {
    // Whitepaper Section 7: under a winner-only policy no amount is
    // published, the winner's included. The circuit constrains this rather
    // than trusting the prover.
    const w = witness({ disclosurePolicy: CONCEAL_WINNING_PRICE });
    expect(w.winningPrice).toBe(0n);
    await accepts(w);
  });

  it("REJECTS a published price under a concealing policy", async () => {
    const w = witness({ disclosurePolicy: CONCEAL_WINNING_PRICE });
    await rejects(
      { ...w, winningPrice: 7400000n },
      "a concealing policy must not be able to publish the price",
    );
  });

  it("REJECTS a zero price under a publishing policy", async () => {
    const w = witness({ disclosurePolicy: DISCLOSE_WINNING_PRICE });
    await rejects({ ...w, winningPrice: 0n }, "a publishing policy must publish the real price");
  });

  it("REJECTS an unknown policy code", async () => {
    // A new policy must not silently fall through to "publish".
    const w = witness();
    await rejects({ ...w, disclosurePolicy: 3n }, "policy 3 is undefined");
    await rejects({ ...w, disclosurePolicy: 0n }, "policy 0 is undefined");
  });
});

// =========================================================================
// The eight attacks of plan Section 14.3. All must fail.
// =========================================================================
describe("plan Section 14.3: every one of these must fail", () => {
  it("1. omitting the CHEAPEST accepted bid", async () => {
    // The attack the whole design exists to stop. Note the root: the honest
    // root covers five bids, and the circuit recomputes the root from all 32
    // slots - so dropping a bid changes the root and the proof cannot match
    // the one the chain holds.
    const honest = witness();
    const without = buildAwardWitness({
      bids: bids().filter((b) => b.submissionIndex !== 2)
        .map((b, i) => ({ ...b, submissionIndex: i })),
      tenderIdField: tf,
      rulesHash: RULES_HASH,
      disclosurePolicy: DISCLOSE_WINNING_PRICE,
    });
    // On its own the shorter set is internally consistent...
    await accepts(without);
    // ...but it does not match the root the chain published.
    expect(without.bidSetRoot).not.toBe(honest.bidSetRoot);
    await rejects(
      { ...without, bidSetRoot: honest.bidSetRoot },
      "a four-bid award must not verify against the five-bid root",
    );
  });

  it("2. omitting a NON-winning accepted bid", async () => {
    const honest = witness();
    const without = buildAwardWitness({
      bids: bids().filter((b) => b.submissionIndex !== 3)
        .map((b, i) => ({ ...b, submissionIndex: i })),
      tenderIdField: tf,
      rulesHash: RULES_HASH,
      disclosurePolicy: DISCLOSE_WINNING_PRICE,
    });
    expect(without.bidSetRoot).not.toBe(honest.bidSetRoot);
    await rejects(
      { ...without, bidSetRoot: honest.bidSetRoot },
      "dropping any accepted bid must fail, not only the cheapest",
    );
  });

  it("3. modifying a bid amount", async () => {
    const w = witness();
    const amounts = [...w.bidAmount];
    amounts[3] = 100n; // make a loser look like the cheapest
    await rejects({ ...w, bidAmount: amounts }, "an altered amount changes its leaf");
  });

  it("4. using a STALE root", async () => {
    const w = witness();
    // The root before the fifth bid arrived.
    const four = buildAwardWitness({
      bids: bids().slice(0, 4),
      tenderIdField: tf,
      rulesHash: RULES_HASH,
      disclosurePolicy: DISCLOSE_WINNING_PRICE,
    });
    await rejects(
      { ...w, bidSetRoot: four.bidSetRoot },
      "a five-bid witness must not verify against a four-bid root",
    );
  });

  it("5. using a WRONG count", async () => {
    const w = witness();
    await rejects({ ...w, submissionCount: 4n }, "an undercount hides the last bid");
    await rejects({ ...w, submissionCount: 6n }, "an overcount activates a padding slot");
  });

  it("6. declaring the SECOND-lowest bid as winner", async () => {
    // Slot 1 at 7,900,000 instead of slot 2 at 7,400,000.
    const w = witness({ winnerIndexOverride: 1 });
    expect(w.winningPrice).toBe(7900000n);
    await rejects(w, "the minimum constraint must reject a non-minimal winner");
  });

  it("7. reversing the order of equal-price bids", async () => {
    // Two bids at the same price: the EARLIER submission must win, and that
    // ordering is the one the validators finalized.
    const tied: OpenedBid[] = [
      { submissionIndex: 0, bidAmount: 8000000n, nullifier: 11n, bidNonce: 1n, ciphertextHashField: 21n },
      { submissionIndex: 1, bidAmount: 7400000n, nullifier: 22n, bidNonce: 2n, ciphertextHashField: 22n },
      { submissionIndex: 2, bidAmount: 7400000n, nullifier: 33n, bidNonce: 3n, ciphertextHashField: 23n },
    ];
    const honest = buildAwardWitness({
      bids: tied, tenderIdField: tf, rulesHash: RULES_HASH,
      disclosurePolicy: DISCLOSE_WINNING_PRICE,
    });
    expect(honest.winnerIndex).toBe(1n);
    await accepts(honest);

    const later = buildAwardWitness({
      bids: tied, tenderIdField: tf, rulesHash: RULES_HASH,
      disclosurePolicy: DISCLOSE_WINNING_PRICE,
      winnerIndexOverride: 2,
    });
    await rejects(later, "the later of two equal bids must not win");
  });

  it("8. reusing the proof for another tender", async () => {
    const w = witness();
    await rejects(
      { ...w, tenderIdField: tenderIdField("FP-00015") },
      "tenderIdField is bound into every commitment and leaf",
    );
  });
});

describe("further soundness checks", () => {
  it("rejects a winner in an INACTIVE slot", async () => {
    // Slot 7 is padding. Its amount is zero, so without the active-slot
    // constraint it would look like the cheapest bid of all.
    const w = witness();
    await rejects({ ...w, winnerIndex: 7n }, "a padding slot must not be able to win");
  });

  it("values in slots beyond submissionCount are INERT", async () => {
    /**
     * Not a rejection test, and it took a failing test to see why.
     *
     * An earlier version of this asserted that a bid parked in slot 6 (beyond
     * a count of 5) must be REJECTED. It was accepted, which looked like a
     * completeness hole. It is not: every slot at or above the count is
     * forced to `DOMAIN_PADDING_V1` regardless of its witness values, the
     * minimum and tie-break constraints are gated on `active[i]`, the
     * nullifier-distinctness check is gated on both slots being active, and
     * `winnerIndex` must select an active slot. So the smuggled values have
     * no path to influence anything.
     *
     * The right assertion is therefore that they are inert - the root is
     * byte-identical to the honest one, so the proof still has to match the
     * root the chain published, and the extra bid buys the prover nothing.
     */
    const honest = witness();
    const nullifier = [...honest.nullifier];
    const bidAmount = [...honest.bidAmount];
    nullifier[6] = 4242n;
    bidAmount[6] = 1n; // cheaper than every real bid
    const smuggled = { ...honest, nullifier, bidAmount };

    await accepts(smuggled);
    expect(smuggled.bidSetRoot).toBe(honest.bidSetRoot);
    // And it still cannot win, because the winner must be in an active slot.
    await rejects(
      { ...smuggled, winnerIndex: 6n },
      "an inactive slot must not be able to win even with the cheapest amount",
    );
  });

  it("rejects a winnerCommitment that is not the winner's", async () => {
    const w = witness();
    const other = bids()[0];
    await rejects(
      {
        ...w,
        winnerCommitment: bidCommitment({
          bidAmount: other.bidAmount,
          bidNonce: other.bidNonce,
          tenderIdField: tf,
          nullifier: other.nullifier,
        }),
      },
      "the commitment must belong to the winning slot",
    );
  });

  it("rejects a duplicated nullifier across active slots", async () => {
    // The chain already rejects a duplicate nullifier at acceptance, so this
    // is unreachable in a set the chain produced. Constrained anyway: without
    // it, an authority could repeat one real bid and 'win' with a cheap
    // duplicate, and the only thing in the way would be a property of a
    // different contract.
    const dup = bids().map((b, i) => (i === 3 ? { ...b, nullifier: bids()[0].nullifier } : b));
    const w = buildAwardWitness({
      bids: dup, tenderIdField: tf, rulesHash: RULES_HASH,
      disclosurePolicy: DISCLOSE_WINNING_PRICE,
    });
    await rejects(w, "two active slots must not share a nullifier");
  });

  it("rejects a bid amount that does not fit 64 bits", async () => {
    // Range checks come BEFORE any comparison. An unbounded amount could wrap
    // the field and appear smaller than every other bid.
    const w = witness();
    const amounts = [...w.bidAmount];
    amounts[4] = 1n << 64n;
    await rejects({ ...w, bidAmount: amounts }, "amounts are bounded at 2^64");
  });

  it("rejects rulesHash limbs wider than 128 bits", async () => {
    // The limbs are a lossless 128+128 split of a 32-byte hash (spec
    // Section 4). An out-of-range limb would reconstruct to one value under
    // the circuit's arithmetic and another under the adapter's, so the range
    // is constrained here.
    const w = witness();
    await rejects({ ...w, rulesHashLo: 1n << 128n }, "the low limb is 128 bits");
    await rejects({ ...w, rulesHashHi: 1n << 128n }, "the high limb is 128 bits");
  });

  it("the rulesHash limbs are NOT bound inside the circuit, and need not be", async () => {
    /**
     * Another test that had to fail before it was right.
     *
     * It originally asserted that incrementing `rulesHashHi` must be
     * REJECTED. The circuit accepted it, and that is correct: the limbs are
     * public signals, so changing them changes the statement being proved.
     * The result is a valid proof of a DIFFERENT claim, not a forged proof of
     * this one.
     *
     * The binding to a specific tender lives in two places, neither of them
     * the circuit:
     *
     *   1. Groth16 itself - a proof verifies only against the public signals
     *      it was generated for.
     *   2. The verifier adapter, which derives the limbs from the tender's
     *      stored `rulesHash` and refuses limbs it did not itself derive.
     *
     * `eligibility.circom` says the same thing in a comment and deliberately
     * adds no decorative constraint, because one would suggest the binding
     * lives in the circuit when it does not. The enforcement is tested at the
     * contract level: EligibilityVerifier's "rejects limbs that do not
     * reconstruct the stored rulesHash" and "rejects swapped hi and lo limbs".
     */
    const w = witness();
    const differentRules = { ...w, rulesHashHi: w.rulesHashHi + 1n };
    await accepts(differentRules);
    // In range, so the circuit is satisfied - and useless on-chain, because
    // the adapter supplies the limbs from storage.
    expect(differentRules.rulesHashHi).toBeLessThan(1n << 128n);
  });

  it("rejects a zero submissionCount", async () => {
    const w = witness();
    await rejects({ ...w, submissionCount: 0n }, "no bids means no winner");
  });

  it("the TypeScript winner selection agrees with the circuit's rule", () => {
    expect(selectWinner(bids()).submissionIndex).toBe(2);
    const tied: OpenedBid[] = [
      { submissionIndex: 0, bidAmount: 5n, nullifier: 1n, bidNonce: 1n, ciphertextHashField: 1n },
      { submissionIndex: 1, bidAmount: 5n, nullifier: 2n, bidNonce: 2n, ciphertextHashField: 2n },
    ];
    expect(selectWinner(tied).submissionIndex).toBe(0);
  });

  it("refuses to build a witness beyond MAX_BIDS", () => {
    const many: OpenedBid[] = Array.from({ length: MAX_BIDS + 1 }, (_, i) => ({
      submissionIndex: i, bidAmount: 1000n + BigInt(i),
      nullifier: BigInt(i + 1), bidNonce: 1n, ciphertextHashField: 1n,
    }));
    expect(() =>
      buildAwardWitness({
        bids: many, tenderIdField: tf, rulesHash: RULES_HASH,
        disclosurePolicy: DISCLOSE_WINNING_PRICE,
      }),
    ).toThrow(/exceeds MAX_BIDS/);
  });
});
