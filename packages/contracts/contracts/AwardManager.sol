// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IFairProofErrors} from "./interfaces/IFairProofErrors.sol";
import {IAwardVerifier} from "./interfaces/IAwardVerifier.sol";
import {FairProofEncoding} from "./lib/FairProofEncoding.sol";
import {Governance} from "./Governance.sol";
import {DeadlineStatus} from "./DeadlineStatus.sol";
import {OpeningManager} from "./OpeningManager.sol";
import {SealedBid} from "./SealedBid.sol";
import {TenderRegistry} from "./TenderRegistry.sol";

/**
 * @title AwardManager
 * @notice Records the award, against a proof that the winner is the lowest
 *         qualified price over the COMPLETE accepted bid set.
 *
 * @dev Development plan Section 14, whitepaper Section 7.
 *
 *      WHO PROVES, AND WHY IT IS SAFE. The procurement authority is the
 *      prover, because after the opening ceremony it is the only party holding
 *      every opened bid. It receives only `bidAmount` and `bidNonce` per bid -
 *      never any `subjectSecret` - so the authority proving the award costs
 *      bidders no privacy beyond what the award itself discloses.
 *
 *      THE SAME RULE AS THE ELIGIBILITY ADAPTER: the contract decides the
 *      public signals. Six of the eight are read out of chain state. The
 *      authority supplies only `winnerCommitment` and `winningPrice`, and even
 *      those are cross-checked - the commitment must belong to an accepted
 *      bid, and the price must be zero unless the frozen disclosure policy
 *      permits publishing it.
 *
 *      This is what forecloses two of the eight attacks in plan Section 14.3
 *      at the contract level rather than only in the circuit:
 *
 *        - "use a stale root": `bidSetRoot` comes from `SealedBid`, so the
 *          only root that can be proved against is the current one.
 *        - "use a wrong count": `submissionCount` likewise.
 *
 *      EVERY ACCEPTED BID MUST BE OPENED FIRST. An award over a subset would
 *      be an award over an incomplete set, which is precisely what the
 *      completeness claim forbids. If some bid genuinely cannot be opened -
 *      a committee that will not act, a ciphertext nobody can retrieve - the
 *      correct outcome is CANCELLATION with a recorded reason (whitepaper
 *      Section 14), not an award over what happened to open.
 *
 *      VERSION PINNING WITHOUT A REGISTRY. Each deployment of this contract
 *      is bound to one immutable verifier and one circuit version, and it
 *      refuses any tender whose frozen `verifierVersion` differs. A new
 *      circuit version means a new AwardManager; an in-flight tender pinned
 *      to the old version keeps being awarded under the logic it was
 *      activated with, because this contract cannot be pointed at a different
 *      verifier. That is the whitepaper Section 14 guarantee - "timelocked
 *      verifier upgrades never alter a running tender" - obtained
 *      structurally rather than by a guard that could be edited.
 */
contract AwardManager is IFairProofErrors {
    /// @notice Public signals in the award circuit. Encoding spec Section 17.
    uint256 public constant PUBLIC_SIGNAL_COUNT = 8;

    /// @notice Disclosure policy codes. Must match TenderRegistry and the circuit.
    uint8 public constant DISCLOSE_WINNING_PRICE = 1;
    uint8 public constant CONCEAL_WINNING_PRICE = 2;

    struct Award {
        uint256 winnerCommitment;
        /// @dev Zero when the disclosure policy conceals it.
        uint256 winningPrice;
        uint256 bidSetRoot;
        uint256 submissionCount;
        uint8 winnerSubmissionIndex;
        uint8 disclosurePolicy;
        uint64 awardedAt;
        address recordedBy;
        bool recorded;
    }

    Governance public immutable governance;
    TenderRegistry public immutable tenderRegistry;
    SealedBid public immutable sealedBid;
    OpeningManager public immutable openingManager;
    DeadlineStatus public immutable deadlineStatus;
    IAwardVerifier public immutable verifier;

    /// @notice The circuit version this deployment enforces. See the header.
    uint32 public immutable circuitVersion;
    /// @notice sha256 of the canonical verification-key JSON, for the record.
    bytes32 public immutable vkeyHash;
    /// @notice Where the ceremony transcript for this verifier is published.
    string public transcriptUri;

    mapping(bytes32 => Award) private _awards;

    error TenderNotClosed(bytes32 tenderId, uint8 state);
    error AlreadyAwarded(bytes32 tenderId);
    error NoAcceptedBids(bytes32 tenderId);
    error VerifierVersionMismatch(uint32 tenderPins, uint32 thisEnforces);
    error BidNotOpened(bytes32 tenderId, uint8 bidIndex, uint8 sharesAccepted, uint8 threshold);
    error WinnerNotAnAcceptedBid(uint256 winnerCommitment);
    error WinnerStatusNotProven(bytes32 tenderId, uint8 bidIndex);
    error PriceMustBeConcealed(uint8 disclosurePolicy);
    error PriceMustBePublished(uint8 disclosurePolicy);
    error UnsupportedDisclosurePolicy(uint8 disclosurePolicy);
    error AwardProofRejected(bytes32 tenderId);
    error NotAwarded(bytes32 tenderId);

    event AwardRecorded(
        bytes32 indexed tenderId,
        uint256 winnerCommitment,
        uint256 winningPrice,
        uint8 winnerSubmissionIndex,
        uint256 bidSetRoot,
        uint256 submissionCount,
        uint8 disclosurePolicy,
        address recordedBy
    );

    constructor(
        Governance governance_,
        TenderRegistry tenderRegistry_,
        SealedBid sealedBid_,
        OpeningManager openingManager_,
        DeadlineStatus deadlineStatus_,
        IAwardVerifier verifier_,
        uint32 circuitVersion_,
        bytes32 vkeyHash_,
        string memory transcriptUri_
    ) {
        governance = governance_;
        tenderRegistry = tenderRegistry_;
        sealedBid = sealedBid_;
        openingManager = openingManager_;
        deadlineStatus = deadlineStatus_;
        verifier = verifier_;
        circuitVersion = circuitVersion_;
        vkeyHash = vkeyHash_;
        transcriptUri = transcriptUri_;
    }

    // --------------------------------------------------------- public signals

    /**
     * @notice The exact eight signals an award proof for this tender must
     *         carry.
     *
     * @dev Published as a view function so the authority's prover reads them
     *      from the chain rather than from its own bookkeeping, and so the
     *      independent verifier can reproduce the check. Six of the eight are
     *      chain state; only the winner's commitment and the price come from
     *      the caller.
     */
    function expectedPublicSignals(
        bytes32 tenderId,
        uint256 winnerCommitment,
        uint256 winningPrice
    ) public view returns (uint256[PUBLIC_SIGNAL_COUNT] memory signals) {
        TenderRegistry.Tender memory t = tenderRegistry.getTender(tenderId);
        (uint256 hi, uint256 lo) = FairProofEncoding.toLimbs(t.rulesHash);

        signals[0] = t.tenderIdField;
        signals[1] = hi;
        signals[2] = lo;
        // From SealedBid, never from the caller: this is what makes the
        // "stale root" and "wrong count" attacks unreachable on-chain.
        signals[3] = sealedBid.bidSetRoot(tenderId);
        signals[4] = sealedBid.submissionCount(tenderId);
        signals[5] = winnerCommitment;
        signals[6] = winningPrice;
        signals[7] = t.disclosurePolicy;
    }

    // ---------------------------------------------------------------- award

    /**
     * @notice Record the award for a CLOSED tender.
     *
     * @param winnerSubmissionIndex Which accepted bid won. Supplied so the
     *        contract can confirm the winning commitment belongs to a real
     *        accepted bid without scanning; the circuit keeps the index
     *        private, and publishing it here reveals only a submission
     *        position, which the acceptance events already made public.
     */
    function recordAward(
        bytes32 tenderId,
        uint256 winnerCommitment,
        uint256 winningPrice,
        uint8 winnerSubmissionIndex,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external {
        TenderRegistry.Tender memory t = tenderRegistry.getTender(tenderId);

        // Only the authority that owns the tender. Whitepaper Section 7 makes
        // the authority the prover, and an award recorded by anyone else would
        // not be attributable to the body accountable for it.
        if (msg.sender != t.authority) revert NotAuthority(msg.sender);
        if (t.state != TenderRegistry.State.CLOSED) {
            revert TenderNotClosed(tenderId, uint8(t.state));
        }
        if (_awards[tenderId].recorded) revert AlreadyAwarded(tenderId);
        if (t.verifierVersion != circuitVersion) {
            revert VerifierVersionMismatch(t.verifierVersion, circuitVersion);
        }

        uint256 count = sealedBid.submissionCount(tenderId);
        if (count == 0) revert NoAcceptedBids(tenderId);

        // Every accepted bid must have reached the opening threshold. An
        // award over a subset is an award over an incomplete set.
        _requireAllOpened(tenderId, uint8(count));

        // The winner must be an accepted bid. The circuit proves the winning
        // commitment is the minimum over the set it was given; this confirms
        // the set is the chain's.
        SealedBid.Bid memory winner = sealedBid.getBid(tenderId, winnerSubmissionIndex);
        if (winner.bidCommitment != winnerCommitment) {
            revert WinnerNotAnAcceptedBid(winnerCommitment);
        }

        // The winner must be provably unrevoked AT THE DEADLINE, against the
        // root pinned when the tender closed. Without this, "unrevoked" would
        // be inferred from the snapshot that was current when the bid was
        // submitted, and a firm revoked in between could still be awarded a
        // contract it is no longer qualified to hold (whitepaper Section 5).
        //
        // Required for the WINNER only. Requiring it of every bidder would let
        // any loser block the award simply by not acting. A cheaper bidder who
        // WAS revoked cannot be excluded by the authority either - the award
        // circuit enforces the minimum over the complete accepted set - so
        // such a tender has no valid award proof and must be cancelled and
        // reissued. See the note on DeadlineStatus.
        if (!deadlineStatus.isProven(tenderId, winnerSubmissionIndex)) {
            revert WinnerStatusNotProven(tenderId, winnerSubmissionIndex);
        }

        // The disclosure policy is frozen in the tender. The circuit
        // constrains the same relationship; enforcing it here as well means a
        // reader of the award record does not have to trust the circuit to
        // know the policy was honoured.
        if (t.disclosurePolicy == CONCEAL_WINNING_PRICE) {
            if (winningPrice != 0) revert PriceMustBeConcealed(t.disclosurePolicy);
        } else if (t.disclosurePolicy == DISCLOSE_WINNING_PRICE) {
            if (winningPrice == 0) revert PriceMustBePublished(t.disclosurePolicy);
        } else {
            // No fallthrough to "publish" for an unrecognised policy.
            revert UnsupportedDisclosurePolicy(t.disclosurePolicy);
        }

        uint256[PUBLIC_SIGNAL_COUNT] memory signals =
            expectedPublicSignals(tenderId, winnerCommitment, winningPrice);
        if (!verifier.verifyProof(proofA, proofB, proofC, signals)) {
            revert AwardProofRejected(tenderId);
        }

        _awards[tenderId] = Award({
            winnerCommitment: winnerCommitment,
            winningPrice: winningPrice,
            bidSetRoot: signals[3],
            submissionCount: count,
            winnerSubmissionIndex: winnerSubmissionIndex,
            disclosurePolicy: t.disclosurePolicy,
            awardedAt: uint64(block.timestamp),
            recordedBy: msg.sender,
            recorded: true
        });

        emit AwardRecorded(
            tenderId,
            winnerCommitment,
            winningPrice,
            winnerSubmissionIndex,
            signals[3],
            count,
            t.disclosurePolicy,
            msg.sender
        );
    }

    /**
     * @dev Require that every accepted bid reached the 3-of-5 opening
     *      threshold.
     *
     *      Bounded by MAX_BIDS = 32, so the loop cannot be made expensive by
     *      an attacker. The error names the first bid that is not ready and
     *      how many shares it has, because "the award reverted" is useless to
     *      an authority trying to work out which committee member has not
     *      acted.
     */
    function _requireAllOpened(bytes32 tenderId, uint8 count) private view {
        for (uint8 i = 0; i < count; i++) {
            (, uint8 accepted, uint8 threshold, bool ready) =
                openingManager.openingStatus(tenderId, i);
            if (!ready) revert BidNotOpened(tenderId, i, accepted, threshold);
        }
    }

    // -------------------------------------------------------------- reading

    function getAward(bytes32 tenderId) external view returns (Award memory) {
        Award memory a = _awards[tenderId];
        if (!a.recorded) revert NotAwarded(tenderId);
        return a;
    }

    function isAwarded(bytes32 tenderId) external view returns (bool) {
        return _awards[tenderId].recorded;
    }

    /**
     * @notice How many accepted bids are still unopened.
     * @dev For the UI, so it can say "3 of 5 bids opened" instead of
     *      presenting an award button that reverts.
     */
    function openedCount(bytes32 tenderId) external view returns (uint256 opened, uint256 total) {
        total = sealedBid.submissionCount(tenderId);
        for (uint8 i = 0; i < total; i++) {
            (, , , bool ready) = openingManager.openingStatus(tenderId, i);
            if (ready) opened++;
        }
    }
}
