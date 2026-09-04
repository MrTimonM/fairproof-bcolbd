pragma circom 2.2.2;

include "constants.circom";
include "commitments.circom";
include "merkle.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/**
 * The award circuit. Whitepaper Section 7, development plan Section 14.
 *
 * Proves that the published winner is the lowest-priced bid over the COMPLETE
 * accepted set, without revealing any losing amount.
 *
 * WHO PROVES THIS. The procurement authority, because after the opening
 * ceremony it is the only party holding every opened bid. It receives only
 * `bidAmount` and `bidNonce` per bid - never any `subjectSecret` - so proving
 * the award costs the bidders no privacy beyond what the award itself
 * discloses.
 *
 * THE ONE DESIGN DECISION THAT MATTERS.
 *
 * The circuit recomputes the ENTIRE accumulator root from all 32 slots and
 * asserts it equals the public `bidSetRoot`. It deliberately does NOT take 32
 * independent Merkle membership proofs.
 *
 * Membership proves each leaf it is given is present. It says nothing about
 * leaves it was not given - so an authority that simply omitted the cheapest
 * bid could still produce 31 valid membership proofs and a valid award over
 * the remaining set. That is the "dropped accepted bid" attack, and
 * recomputing the whole root is what forecloses it: the root is a function of
 * every slot, so a missing bid changes it and the proof fails against the root
 * the chain already holds.
 *
 * PADDING IS NOT ZERO. Unused slots carry DOMAIN_PADDING_V1. A zero leaf is
 * indistinguishable from an empty subtree, which would let a real leaf be
 * swapped for an apparently-empty slot without changing the root.
 *
 * MAX_BIDS IS 32 AND IS NOT NEGOTIABLE. Whitepaper Section 7 states the
 * prototype supports 32 and Section 19.3 promises timings at 5 / 10 / 25 bids
 * "in the same padded circuit". Shipping 8 or 16 would contradict a submitted
 * document in a way a reviewer can check in one line.
 */

/**
 * Select `values[index]` for a private `index`.
 *
 * Implemented as a sum of equality indicators rather than an array lookup,
 * because a circuit has no dynamic indexing. The indicators are also summed
 * and constrained to exactly 1, so a witness cannot select nothing (which
 * would make the selected value zero and let a winner be invented) or select
 * two slots at once.
 */
template Selector(n) {
    signal input values[n];
    signal input index;
    signal output out;

    signal isSelected[n];
    signal terms[n];
    var acc = 0;
    var indicatorSum = 0;

    component eq[n];
    for (var i = 0; i < n; i++) {
        eq[i] = IsEqual();
        eq[i].in[0] <== index;
        eq[i].in[1] <== i;
        isSelected[i] <== eq[i].out;
        terms[i] <== isSelected[i] * values[i];
        acc += terms[i];
        indicatorSum += isSelected[i];
    }
    indicatorSum === 1;
    out <== acc;
}

/**
 * @param depth      Merkle depth of the bid accumulator (5).
 * @param maxBids    2**depth (32).
 * @param amountBits Bit width of a bid amount. Spec Section 14 caps amounts at
 *                   2^64, so comparisons are done over 64 bits; comparing over
 *                   the full field would be both wasteful and unsound, since
 *                   LessThan requires its inputs to be bounded.
 */
template Award(depth, maxBids, amountBits) {
    // ---- public ----------------------------------------------------------
    signal input tenderIdField;
    signal input rulesHashHi;
    signal input rulesHashLo;
    signal input bidSetRoot;
    signal input submissionCount;
    signal input winnerCommitment;
    signal input winningPrice;
    signal input disclosurePolicy;

    // ---- private ---------------------------------------------------------
    signal input nullifier[maxBids];
    signal input bidAmount[maxBids];
    signal input bidNonce[maxBids];
    signal input ciphertextHashField[maxBids];
    /// @dev Which slot won. Private, because revealing it would reveal which
    ///      submission position the winner used.
    signal input winnerIndex;

    // =====================================================================
    // 1. Ranges first.
    //
    // Every comparator below assumes its inputs fit in `amountBits`. An
    // unbounded amount would let a witness wrap around the field and appear
    // smaller than every other bid. Range checks therefore come BEFORE any
    // comparison, not after.
    // =====================================================================
    component amountBitsCheck[maxBids];
    for (var i = 0; i < maxBids; i++) {
        amountBitsCheck[i] = Num2Bits(amountBits);
        amountBitsCheck[i].in <== bidAmount[i];
    }

    // submissionCount in [1, maxBids]. Zero accepted bids has no winner, so a
    // proof claiming one is a contradiction rather than an edge case.
    component countBits = Num2Bits(8);
    countBits.in <== submissionCount;
    component countAtLeastOne = LessEqThan(8);
    countAtLeastOne.in[0] <== 1;
    countAtLeastOne.in[1] <== submissionCount;
    countAtLeastOne.out === 1;
    component countAtMostMax = LessEqThan(8);
    countAtMostMax.in[0] <== submissionCount;
    countAtMostMax.in[1] <== maxBids;
    countAtMostMax.out === 1;

    // winnerIndex must be a real slot index.
    component winnerIndexBits = Num2Bits(depth);
    winnerIndexBits.in <== winnerIndex;

    // =====================================================================
    // 2. Which slots are active.
    //
    // active[i] = (i < submissionCount). Every inactive slot is forced to the
    // padding leaf below, so the witness cannot smuggle an extra bid into a
    // slot beyond the count the chain published.
    // =====================================================================
    signal active[maxBids];
    component isActive[maxBids];
    for (var i = 0; i < maxBids; i++) {
        isActive[i] = LessThan(8);
        isActive[i].in[0] <== i;
        isActive[i].in[1] <== submissionCount;
        active[i] <== isActive[i].out;
    }

    // =====================================================================
    // 3. Rebuild every leaf, then the whole root.
    // =====================================================================
    component commitment[maxBids];
    component leaf[maxBids];
    signal leafValue[maxBids];
    signal activeLeaf[maxBids];

    for (var i = 0; i < maxBids; i++) {
        commitment[i] = BidCommitment();
        commitment[i].bidAmount <== bidAmount[i];
        commitment[i].bidNonce <== bidNonce[i];
        commitment[i].tenderIdField <== tenderIdField;
        commitment[i].nullifier <== nullifier[i];

        leaf[i] = BidLeaf();
        leaf[i].nullifier <== nullifier[i];
        leaf[i].bidCommitment <== commitment[i].out;
        leaf[i].ciphertextHashField <== ciphertextHashField[i];
        leaf[i].submissionIndex <== i;

        // An active slot contributes its computed leaf; an inactive slot
        // contributes exactly DOMAIN_PADDING_V1. Written as one linear
        // combination so there is no branch a witness could take differently.
        activeLeaf[i] <== active[i] * leaf[i].out;
        leafValue[i] <== activeLeaf[i] + (1 - active[i]) * DOMAIN_PADDING_V1();
    }

    component tree = FullMerkleRoot(depth);
    for (var i = 0; i < maxBids; i++) {
        tree.leaves[i] <== leafValue[i];
    }
    tree.root === bidSetRoot;

    // =====================================================================
    // 4. Nullifiers are distinct across active slots.
    //
    // The chain already rejects a duplicate nullifier at acceptance, so this
    // cannot happen in a set the chain produced. It is constrained anyway:
    // without it, an authority could pad the witness by repeating one real bid
    // and then "win" with a cheap duplicate of it, and the only thing standing
    // in the way would be a property of a different contract.
    // =====================================================================
    component nullifierDistinct[maxBids][maxBids];
    signal bothActive[maxBids][maxBids];
    for (var i = 0; i < maxBids; i++) {
        for (var j = i + 1; j < maxBids; j++) {
            nullifierDistinct[i][j] = IsEqual();
            nullifierDistinct[i][j].in[0] <== nullifier[i];
            nullifierDistinct[i][j].in[1] <== nullifier[j];
            bothActive[i][j] <== active[i] * active[j];
            // If both slots are active their nullifiers must differ.
            nullifierDistinct[i][j].out * bothActive[i][j] === 0;
        }
    }

    // =====================================================================
    // 5. The winner is active, and is the one committed to.
    // =====================================================================
    component winnerActive = Selector(maxBids);
    for (var i = 0; i < maxBids; i++) {
        winnerActive.values[i] <== active[i];
    }
    winnerActive.index <== winnerIndex;
    winnerActive.out === 1;

    component winnerCommitmentSel = Selector(maxBids);
    for (var i = 0; i < maxBids; i++) {
        winnerCommitmentSel.values[i] <== commitment[i].out;
    }
    winnerCommitmentSel.index <== winnerIndex;
    winnerCommitmentSel.out === winnerCommitment;

    component winnerAmountSel = Selector(maxBids);
    for (var i = 0; i < maxBids; i++) {
        winnerAmountSel.values[i] <== bidAmount[i];
    }
    winnerAmountSel.index <== winnerIndex;
    signal winnerAmount;
    winnerAmount <== winnerAmountSel.out;

    // =====================================================================
    // 6. The winner is the minimum over ACTIVE slots.
    //
    // For every slot: either it is inactive, or winnerAmount <= its amount.
    // Quantifying over inactive slots too would be wrong - their amounts are
    // unconstrained witness values and could be forced to zero.
    // =====================================================================
    component notGreater[maxBids];
    for (var i = 0; i < maxBids; i++) {
        notGreater[i] = LessEqThan(amountBits);
        notGreater[i].in[0] <== winnerAmount;
        notGreater[i].in[1] <== bidAmount[i];
        // active[i] * (1 - notGreater[i]) === 0, i.e. an active slot must not
        // be cheaper than the winner.
        active[i] * (1 - notGreater[i].out) === 0;
    }

    // =====================================================================
    // 7. Ties break on submission sequence.
    //
    // Among active slots at exactly the winning price, the winner must be the
    // EARLIEST. The plan is explicit that this rule "stays inside the
    // validator-ordering trust boundary and must be documented as such": the
    // sequence is the one the validators finalized, so a tie is resolved by
    // consensus ordering rather than by anything the authority chooses.
    // =====================================================================
    component sameAmount[maxBids];
    component winnerEarlier[maxBids];
    signal tiedActive[maxBids];
    for (var i = 0; i < maxBids; i++) {
        sameAmount[i] = IsEqual();
        sameAmount[i].in[0] <== bidAmount[i];
        sameAmount[i].in[1] <== winnerAmount;

        winnerEarlier[i] = LessEqThan(depth + 1);
        winnerEarlier[i].in[0] <== winnerIndex;
        winnerEarlier[i].in[1] <== i;

        tiedActive[i] <== active[i] * sameAmount[i].out;
        tiedActive[i] * (1 - winnerEarlier[i].out) === 0;
    }

    // =====================================================================
    // 8. The disclosure policy governs whether the price is published.
    //
    // Whitepaper Section 7: under a winner-only policy the losing amounts are
    // never published - and neither is the winning one. `winningPrice` is
    // therefore the winner's amount when the policy discloses it and EXACTLY
    // ZERO otherwise, constrained rather than left to the prover.
    //
    // Policy codes match TenderRegistry: 1 = PUBLISH_WINNING_PRICE,
    // 2 = WINNER_ONLY_POST_AWARD. Any other value is rejected, so a new policy
    // cannot silently fall through to "publish".
    // =====================================================================
    component publishes = IsEqual();
    publishes.in[0] <== disclosurePolicy;
    publishes.in[1] <== 1;
    component conceals = IsEqual();
    conceals.in[0] <== disclosurePolicy;
    conceals.in[1] <== 2;
    publishes.out + conceals.out === 1;

    winningPrice === publishes.out * winnerAmount;

    // =====================================================================
    // 9. rulesHash limbs are range-checked.
    //
    // They travel as two 128-bit halves (spec Section 4). Without the range
    // check a prover could offer limbs that reconstruct to the right value in
    // one interpretation and something else in another; the verifier adapter
    // reconstructs and compares, so the two must agree on the split.
    // =====================================================================
    component hiBits = Num2Bits(128);
    hiBits.in <== rulesHashHi;
    component loBits = Num2Bits(128);
    loBits.in <== rulesHashLo;
}

component main {
    public [
        tenderIdField,
        rulesHashHi,
        rulesHashLo,
        bidSetRoot,
        submissionCount,
        winnerCommitment,
        winningPrice,
        disclosurePolicy
    ]
} = Award(BID_TREE_DEPTH(), MAX_BIDS(), 64);
