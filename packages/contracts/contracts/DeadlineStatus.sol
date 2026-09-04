// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IFairProofErrors} from "./interfaces/IFairProofErrors.sol";
import {EligibilityVerifier} from "./EligibilityVerifier.sol";
import {IssuerRegistry} from "./IssuerRegistry.sol";
import {SealedBid} from "./SealedBid.sol";
import {TenderRegistry} from "./TenderRegistry.sol";

/**
 * @title DeadlineStatus
 * @notice Close-time credential status proofs against the pinned deadline root.
 *
 * @dev Whitepaper Section 5, development plan Section 9.1.1. Build order
 *      step 13.
 *
 *      THE PROBLEM THIS SOLVES. A bidder's credential was unrevoked when they
 *      submitted. Between submission and the deadline it may have been
 *      revoked - a lapsed certification, a disbarment, a compromised issuer
 *      key. Without a close-time check, "unrevoked" would be inferred from an
 *      older snapshot, and a firm could be awarded a contract it was no longer
 *      qualified to hold.
 *
 *      `TenderRegistry` already pins the then-current revocation root as the
 *      tender's `deadlineRevocationRoot` at the moment it closes, one-shot, so
 *      a later revocation cannot be retroactively hidden or introduced. This
 *      contract is where a bidder proves their credential is still clean
 *      against exactly that root.
 *
 *      WHAT IS PROVED IS THE WHOLE ELIGIBILITY STATEMENT, re-evaluated. The
 *      same circuit, the same pinned verifier version, the same nullifier and
 *      bid commitment - only the revocation root differs. So a status proof
 *      says "this bidder would still pass every clause today", which is
 *      stronger than bare non-revocation and costs no second ceremony.
 *
 * @dev WHAT HAPPENS IF A CHEAPER BIDDER WAS REVOKED, stated plainly.
 *
 *      `AwardManager` requires a status proof for the WINNER, so the awarded
 *      party is provably unrevoked at the deadline. It does NOT let the
 *      authority exclude a cheaper bid by declaring it revoked, because the
 *      award circuit enforces the minimum over the complete accepted set.
 *
 *      That means a tender whose cheapest bidder was revoked before the
 *      deadline has NO valid award proof: the honest winner is not the
 *      minimum, and the revoked bidder cannot produce a status proof. The
 *      tender must then be cancelled with a recorded reason and reissued,
 *      which is precisely the remedy whitepaper Section 14 commits to
 *      ("cancellation and versioned reissue" instead of in-place amendment).
 *
 *      This is a deliberate choice of failure mode. A blunt cancellation is
 *      recoverable and public; an award to a non-minimum bidder on the
 *      authority's unverified assertion that someone else was revoked is
 *      neither. It is listed as a PARTIAL row in the traceability table
 *      rather than presented as full exclusion support.
 */
contract DeadlineStatus is IFairProofErrors {
    TenderRegistry public immutable tenderRegistry;
    IssuerRegistry public immutable issuerRegistry;
    SealedBid public immutable sealedBid;
    EligibilityVerifier public immutable eligibilityVerifier;

    struct Status {
        bool proven;
        uint64 provenAt;
        address submitter;
        /// @dev The root the proof was checked against, recorded so a reader
        ///      does not have to re-derive which root was current.
        bytes32 deadlineRoot;
    }

    /// @dev tenderId => bidIndex => status.
    mapping(bytes32 => mapping(uint8 => Status)) private _status;

    error TenderNotClosed(bytes32 tenderId, uint8 state);
    error NoSuchBid(bytes32 tenderId, uint8 bidIndex);
    error AlreadyProven(bytes32 tenderId, uint8 bidIndex);
    error StatusProofRejected(bytes32 tenderId, uint8 bidIndex);
    error DeadlineRootNotPinned(bytes32 tenderId);

    event StatusProven(
        bytes32 indexed tenderId,
        uint8 indexed bidIndex,
        uint256 nullifier,
        bytes32 deadlineRoot,
        address submitter
    );

    constructor(
        TenderRegistry tenderRegistry_,
        IssuerRegistry issuerRegistry_,
        SealedBid sealedBid_,
        EligibilityVerifier eligibilityVerifier_
    ) {
        tenderRegistry = tenderRegistry_;
        issuerRegistry = issuerRegistry_;
        sealedBid = sealedBid_;
        eligibilityVerifier = eligibilityVerifier_;
    }

    /**
     * @notice Prove that an accepted bid's credential is unrevoked at the
     *         tender's pinned deadline root.
     *
     * @dev Permissionless in the same sense as bid submission: what authorises
     *      the statement is the proof, not the sender. Only the holder of the
     *      witness can produce it, and gas is free here, so a bidder can
     *      submit from a fresh address and add no correlation channel
     *      (whitepaper Table 4).
     *
     *      The nullifier and bid commitment are NOT taken from the caller -
     *      they are read from the accepted bid record, so a status proof can
     *      only ever be about a bid the chain actually accepted, and it cannot
     *      be filed against the wrong slot.
     */
    function submitStatusProof(
        bytes32 tenderId,
        uint8 bidIndex,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external {
        TenderRegistry.State state = tenderRegistry.getState(tenderId);
        // CLOSED is the only state in which a deadline root exists.
        if (state != TenderRegistry.State.CLOSED) {
            revert TenderNotClosed(tenderId, uint8(state));
        }
        if (bidIndex >= sealedBid.submissionCount(tenderId)) {
            revert NoSuchBid(tenderId, bidIndex);
        }
        if (_status[tenderId][bidIndex].proven) revert AlreadyProven(tenderId, bidIndex);

        bytes32 root = issuerRegistry.deadlineRevocationRoot(tenderId);
        if (root == bytes32(0)) revert DeadlineRootNotPinned(tenderId);

        SealedBid.Bid memory bid = sealedBid.getBid(tenderId, bidIndex);
        if (
            !eligibilityVerifier.verifyDeadlineStatus(
                tenderId,
                bid.nullifier,
                bid.bidCommitment,
                proofA,
                proofB,
                proofC
            )
        ) {
            revert StatusProofRejected(tenderId, bidIndex);
        }

        _status[tenderId][bidIndex] = Status({
            proven: true,
            provenAt: uint64(block.timestamp),
            submitter: msg.sender,
            deadlineRoot: root
        });

        emit StatusProven(tenderId, bidIndex, bid.nullifier, root, msg.sender);
    }

    function isProven(bytes32 tenderId, uint8 bidIndex) external view returns (bool) {
        return _status[tenderId][bidIndex].proven;
    }

    function getStatus(bytes32 tenderId, uint8 bidIndex) external view returns (Status memory) {
        return _status[tenderId][bidIndex];
    }

    /// @notice For the integrity report: how many accepted bids are proven.
    function provenCount(bytes32 tenderId) external view returns (uint256 proven, uint256 total) {
        total = sealedBid.submissionCount(tenderId);
        for (uint8 i = 0; i < total; i++) {
            if (_status[tenderId][i].proven) proven++;
        }
    }
}
