// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IFairProofErrors} from "./interfaces/IFairProofErrors.sol";
import {FairProofEncoding} from "./lib/FairProofEncoding.sol";
import {IncrementalMerkleTree} from "./lib/IncrementalMerkleTree.sol";
import {EligibilityVerifier} from "./EligibilityVerifier.sol";
import {Governance} from "./Governance.sol";
import {TenderRegistry} from "./TenderRegistry.sol";

/**
 * @title SealedBid
 * @notice Bid acceptance and the append-only bid-set accumulator.
 *
 * @dev Development plan Sections 12.5 and 13, whitepaper Sections 5 and 7.
 *
 *      THE CONTRACT ACCUMULATES THE ROOT, NOT THE AUTHORITY. That is the whole
 *      basis of the completeness claim in the award proof: if the authority
 *      computed `bidSetRoot`, it could omit a bid it disliked and the award
 *      proof would still verify against the root it published. So Poseidon
 *      runs on-chain, once per accepted bid, and the root is a consequence of
 *      the accepted set rather than an assertion about it.
 *
 *      WHAT ACCEPTANCE REQUIRES, and why each part is here:
 *
 *      1. Bidding is open. Not merely ACTIVE - the review window must have
 *         elapsed and the deadline must not have passed.
 *      2. The eligibility proof verifies against the tender's FROZEN rules,
 *         with the public signals derived from storage by
 *         `EligibilityVerifier`. The bidder supplies only the nullifier and
 *         the bid commitment.
 *      3. The nullifier is unused for this tender. One bid per credential per
 *         tender; the nullifier is tender-scoped, so the same credential can
 *         bid on a different tender without being linkable.
 *      4. At least two distinct registered replicas signed a receipt for
 *         exactly this `ciphertextHash`. A commitment must never enter
 *         `bidSetRoot` without a retrievable payload behind it, or the award
 *         proof's completeness claim is false and unopenable bids break the
 *         tender.
 *      5. Capacity. `MAX_BIDS` is 32 and the 33rd bid is rejected BEFORE
 *         acceptance, as whitepaper Section 7 requires - not left to the tree
 *         to fail on insert, which would consume the submitter's transaction
 *         for an outcome that was knowable in advance.
 *
 *      THE LEAF HAS FOUR INPUTS. `storageReceiptRoot` is checked at
 *      acceptance and stored in the bid record, but it is deliberately NOT in
 *      the leaf: whitepaper Section 7 fixes the leaf as
 *      Poseidon(nullifier, bidCommitment, ciphertextHashField,
 *      submissionIndex), and adding a fifth input would make every on-chain
 *      root disagree with the award statement the whitepaper publishes.
 */
contract SealedBid is IFairProofErrors {
    using IncrementalMerkleTree for IncrementalMerkleTree.Tree;

    /// @notice Whitepaper Section 7: the award circuit supports 32 bids.
    uint32 public constant MAX_BIDS = 32;
    uint8 public constant BID_TREE_DEPTH = 5;

    /**
     * @notice The STORAGE quorum: two of three replicas.
     * @dev Not the 3-of-5 opening threshold. Two replicas cannot open a bid
     *      and three committee members cannot make a ciphertext retrievable;
     *      the two numbers are never interchangeable.
     */
    uint8 public constant STORAGE_QUORUM = 2;
    uint8 public constant STORAGE_REPLICAS = 3;
    uint8 public constant RECEIPT_TREE_DEPTH = 2;

    /// @dev keccak256("FairProof:receipt:v1"). Spec Section 13.
    bytes32 internal constant RAW_RECEIPT_V1 =
        0x6f914b0c1addf20f03c49bb18eb568ad66529197270c1c525f3867fdef721325;
    /// @dev keccak256("FairProof:receiptSig:v1"). Spec Section 22.
    bytes32 internal constant RAW_RECEIPT_SIG_V1 =
        0xc3ffb182dd3ebfe5535def6710ba4562e2bf2416e6ac55e4ac25fc7e14433ea3;

    /**
     * @notice What the bidder is submitting.
     * @dev Grouped into a struct because the flat parameter list exceeded the
     *      EVM stack, and `viaIR` is unavailable: it inflates the linked
     *      Poseidon libraries past EIP-170 (docs/stage0-evidence.md). Same
     *      constraint as `TenderRegistry.RuleFields` and
     *      `EligibilityVerifier.Registration`.
     */
    struct Submission {
        bytes32 tenderId;
        uint256 nullifier;
        uint256 bidCommitment;
        bytes32 ciphertextHash;
    }

    /// @notice One replica's signed acknowledgement. Spec Sections 13 and 22.
    struct Receipt {
        uint8 replicaId;
        bytes32 contentHash;
        uint64 byteLength;
        /// @dev 65-byte r||s||v, so the signer is recoverable with ecrecover.
        bytes signature;
    }

    struct Bid {
        uint256 nullifier;
        uint256 bidCommitment;
        bytes32 ciphertextHash;
        uint256 storageReceiptRoot;
        uint256 leaf;
        uint64 submittedAt;
        uint8 submissionIndex;
        /// @dev Whoever paid for the transaction. NOT the bidder's identity:
        ///      gas is free here precisely so this can be a fresh address with
        ///      no funding history (whitepaper Table 4's metadata risk).
        address submitter;
    }

    struct Replica {
        address signer;
        bool active;
        string label;
    }

    Governance public immutable governance;
    TenderRegistry public immutable tenderRegistry;
    EligibilityVerifier public immutable eligibilityVerifier;

    mapping(uint8 => Replica) private _replicas;
    uint8 public activeReplicaCount;

    mapping(bytes32 => IncrementalMerkleTree.Tree) private _trees;
    mapping(bytes32 => Bid[]) private _bids;
    /// @dev Tender-scoped, so one credential can bid on many tenders unlinkably.
    mapping(bytes32 => mapping(uint256 => bool)) public nullifierUsed;
    mapping(bytes32 => mapping(bytes32 => bool)) public ciphertextUsed;

    error BiddingNotOpen(bytes32 tenderId);
    error NullifierAlreadyUsed(bytes32 tenderId, uint256 nullifier);
    error CiphertextAlreadySubmitted(bytes32 tenderId, bytes32 ciphertextHash);
    error BidCapacityReached(bytes32 tenderId, uint32 accepted, uint32 max);
    error StorageQuorumNotMet(uint8 valid, uint8 required);
    error TooManyReceipts(uint256 provided, uint8 max);
    error ReceiptsNotOrdered(uint8 previousId, uint8 replicaId);
    error UnknownReplica(uint8 replicaId);
    error InactiveReplica(uint8 replicaId);
    error ReceiptContentMismatch(uint8 replicaId, bytes32 expected, bytes32 actual);
    error ReceiptSignatureInvalid(uint8 replicaId, address recovered, address expected);
    error ReceiptSignatureLength(uint8 replicaId, uint256 length);
    error ReplicaAlreadyRegistered(uint8 replicaId);
    error InvalidReplicaId(uint8 replicaId);
    error ZeroReplicaSigner(uint8 replicaId);
    error DuplicateReplicaSigner(address signer);
    error ZeroCommitment();
    error NoBids(bytes32 tenderId);

    event ReplicaRegistered(uint8 indexed replicaId, address indexed signer, string label);
    event ReplicaStatusChanged(uint8 indexed replicaId, bool active, string reason);
    event BidAccepted(
        bytes32 indexed tenderId,
        uint8 indexed submissionIndex,
        uint256 nullifier,
        uint256 bidCommitment,
        bytes32 ciphertextHash,
        uint256 storageReceiptRoot,
        uint256 leaf,
        uint256 bidSetRoot,
        address submitter
    );

    modifier onlyCouncil() {
        if (!governance.isCouncilMember(msg.sender)) revert NotCouncilMember(msg.sender);
        _;
    }

    modifier notPaused() {
        if (governance.paused()) revert SystemPaused();
        _;
    }

    constructor(
        Governance governance_,
        TenderRegistry tenderRegistry_,
        EligibilityVerifier eligibilityVerifier_
    ) {
        governance = governance_;
        tenderRegistry = tenderRegistry_;
        eligibilityVerifier = eligibilityVerifier_;
    }

    // --------------------------------------------------------------- replicas

    /**
     * @notice Register a ciphertext-store replica's signing key. Council only.
     *
     * @dev One-shot per id. A re-settable replica key would let a captured
     *      council key retroactively make an old receipt verify - or stop it
     *      verifying - and the receipts are what the completeness claim rests
     *      on. A compromised replica is deactivated instead, which stops it
     *      counting towards FUTURE quorums without rewriting past ones.
     */
    function registerReplica(uint8 replicaId, address signer, string calldata label)
        external
        onlyCouncil
    {
        // Zero is reserved: it is the natural value of an unset uint8, and an
        // id that equals "missing" is a bug waiting to be exploited.
        if (replicaId == 0 || replicaId > STORAGE_REPLICAS) revert InvalidReplicaId(replicaId);
        if (signer == address(0)) revert ZeroReplicaSigner(replicaId);
        if (_replicas[replicaId].signer != address(0)) revert ReplicaAlreadyRegistered(replicaId);
        for (uint8 i = 1; i <= STORAGE_REPLICAS; i++) {
            // Two replicas sharing a key are one replica wearing two hats, and
            // would satisfy a 2-of-3 quorum on their own.
            if (_replicas[i].signer == signer) revert DuplicateReplicaSigner(signer);
        }
        _replicas[replicaId] = Replica({signer: signer, active: true, label: label});
        activeReplicaCount += 1;
        emit ReplicaRegistered(replicaId, signer, label);
    }

    /// @notice Activate or deactivate a replica, with a recorded reason.
    function setReplicaStatus(uint8 replicaId, bool active, string calldata reason)
        external
        onlyCouncil
    {
        Replica storage r = _replicas[replicaId];
        if (r.signer == address(0)) revert UnknownReplica(replicaId);
        if (bytes(reason).length == 0) revert ReasonRequired();
        if (r.active != active) {
            r.active = active;
            activeReplicaCount = active ? activeReplicaCount + 1 : activeReplicaCount - 1;
        }
        emit ReplicaStatusChanged(replicaId, active, reason);
    }

    function getReplica(uint8 replicaId) external view returns (Replica memory) {
        return _replicas[replicaId];
    }

    // ------------------------------------------------------------ submission

    /**
     * @notice Submit a sealed bid.
     *
     * @dev Permissionless on purpose. Anyone may pay for the transaction; what
     *      authorises the bid is the zero-knowledge proof, not the sender.
     *      Since gas is free on this network, a bidder can submit from a fresh
     *      zero-balance address, which removes the wallet-funding correlation
     *      channel whitepaper Table 4 lists as a residual metadata risk.
     *
     * @param receipts MUST be ordered by `replicaId` ascending, because the
     *        receipt root is order-dependent and the contract has to recompute
     *        the same value the bidder did. Sorting them here would cost gas
     *        for something the client already knows; rejecting unordered input
     *        makes the requirement explicit rather than silently accepting a
     *        root that will not match.
     */
    function submitBid(
        Submission calldata s,
        Receipt[] calldata receipts,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external notPaused returns (uint8 submissionIndex, uint256 bidSetRoot_) {
        // ---- 1. the window ------------------------------------------------
        if (!tenderRegistry.isBiddingOpen(s.tenderId)) revert BiddingNotOpen(s.tenderId);

        // ---- 5. capacity, checked BEFORE anything expensive ---------------
        // Whitepaper Section 7 requires the 33rd bid be rejected before
        // acceptance. Checking it first also means a bidder is not charged for
        // a pairing check on a submission that could never succeed.
        uint32 accepted = uint32(_bids[s.tenderId].length);
        if (accepted >= MAX_BIDS) revert BidCapacityReached(s.tenderId, accepted, MAX_BIDS);

        // ---- 3. one bid per credential per tender -------------------------
        if (s.nullifier == 0 || s.bidCommitment == 0) revert ZeroCommitment();
        if (nullifierUsed[s.tenderId][s.nullifier]) {
            revert NullifierAlreadyUsed(s.tenderId, s.nullifier);
        }
        // Two bids sharing a ciphertext would open to the same payload, so one
        // of them is a replay. Cheap to forbid, and it closes a griefing path
        // where a watcher resubmits someone's ciphertext under a new
        // commitment.
        if (ciphertextUsed[s.tenderId][s.ciphertextHash]) {
            revert CiphertextAlreadySubmitted(s.tenderId, s.ciphertextHash);
        }

        // ---- 4. two independent replicas hold the ciphertext --------------
        uint256 receiptRoot = _verifyReceipts(receipts, s.ciphertextHash);

        // ---- 2. the proof, against the tender's frozen rules --------------
        // Last, because it is the most expensive check and every cheaper
        // reason to reject has already been tried. `requireEligibility`
        // reverts rather than returning a boolean, so there is no return value
        // for a future edit to forget to check.
        eligibilityVerifier.requireEligibility(
            s.tenderId,
            s.nullifier,
            s.bidCommitment,
            proofA,
            proofB,
            proofC
        );

        return _accept(s, receiptRoot, uint8(accepted));
    }

    /**
     * @dev Record the accepted bid and append its leaf.
     *
     *      Split out of `submitBid` to keep both within the EVM stack limit,
     *      and because it is the only place that mutates: every check lives
     *      above it, so a reader can see that nothing is written before the
     *      proof verifies.
     */
    function _accept(Submission calldata s, uint256 receiptRoot, uint8 submissionIndex)
        private
        returns (uint8, uint256)
    {
        nullifierUsed[s.tenderId][s.nullifier] = true;
        ciphertextUsed[s.tenderId][s.ciphertextHash] = true;

        IncrementalMerkleTree.Tree storage tree = _trees[s.tenderId];
        if (tree.depth == 0) tree.init(BID_TREE_DEPTH);

        uint256 leaf = FairProofEncoding.bidLeaf(
            s.nullifier,
            s.bidCommitment,
            FairProofEncoding.toField(s.ciphertextHash),
            submissionIndex
        );
        tree.insert(leaf);
        uint256 root = tree.getRoot();

        _bids[s.tenderId].push(
            Bid({
                nullifier: s.nullifier,
                bidCommitment: s.bidCommitment,
                ciphertextHash: s.ciphertextHash,
                storageReceiptRoot: receiptRoot,
                leaf: leaf,
                submittedAt: uint64(block.timestamp),
                submissionIndex: submissionIndex,
                submitter: msg.sender
            })
        );

        // Everything an independent verifier needs to reproduce the root from
        // events alone, without reading storage (plan Section 13).
        emit BidAccepted(
            s.tenderId,
            submissionIndex,
            s.nullifier,
            s.bidCommitment,
            s.ciphertextHash,
            receiptRoot,
            leaf,
            root,
            msg.sender
        );
        return (submissionIndex, root);
    }

    /**
     * @dev Recompute `storageReceiptRoot` and enforce the quorum.
     *
     *      Spec Section 13: leaves ordered by `replicaId` ascending, padded to
     *      four slots with `DOMAIN_PADDING_V1`, accumulated in a depth-2 tree.
     *      The padding value is NOT zero - a zero leaf is indistinguishable
     *      from an empty subtree.
     *
     *      Each signature is recovered and compared against the replica's
     *      registered address. The bidder's client performs the same check
     *      before submitting, but a check that exists only client-side is not
     *      a check: the submission path is public.
     */
    function _verifyReceipts(Receipt[] calldata receipts, bytes32 ciphertextHash)
        private
        view
        returns (uint256 root)
    {
        if (receipts.length > STORAGE_REPLICAS) {
            revert TooManyReceipts(receipts.length, STORAGE_REPLICAS);
        }

        uint256 slots = 1 << RECEIPT_TREE_DEPTH; // 4
        uint256[] memory leaves = new uint256[](slots);
        for (uint256 i = 0; i < slots; i++) {
            leaves[i] = FairProofEncoding.DOMAIN_PADDING_V1;
        }

        uint8 valid = 0;
        uint8 previousId = 0;
        for (uint256 i = 0; i < receipts.length; i++) {
            Receipt calldata r = receipts[i];

            // Strictly increasing: this rejects both unordered input and a
            // duplicate replica, so two receipts from one replica can never
            // pass for two acknowledgements.
            if (r.replicaId <= previousId) revert ReceiptsNotOrdered(previousId, r.replicaId);
            previousId = r.replicaId;

            Replica storage replica = _replicas[r.replicaId];
            if (replica.signer == address(0)) revert UnknownReplica(r.replicaId);
            if (!replica.active) revert InactiveReplica(r.replicaId);

            // The receipt must cover the ciphertext the bidder is submitting,
            // not some other object the replica happens to hold.
            if (r.contentHash != ciphertextHash) {
                revert ReceiptContentMismatch(r.replicaId, ciphertextHash, r.contentHash);
            }
            if (r.signature.length != 65) {
                revert ReceiptSignatureLength(r.replicaId, r.signature.length);
            }

            bytes32 digest = keccak256(
                abi.encodePacked(
                    RAW_RECEIPT_SIG_V1,
                    r.replicaId,
                    r.contentHash,
                    r.byteLength
                )
            );
            address recovered = _recover(digest, r.signature);
            if (recovered != replica.signer) {
                revert ReceiptSignatureInvalid(r.replicaId, recovered, replica.signer);
            }

            leaves[i] = FairProofEncoding.toField(
                keccak256(
                    abi.encodePacked(
                        RAW_RECEIPT_V1,
                        r.replicaId,
                        r.contentHash,
                        r.byteLength,
                        r.signature
                    )
                )
            );
            valid += 1;
        }

        if (valid < STORAGE_QUORUM) revert StorageQuorumNotMet(valid, STORAGE_QUORUM);

        // Depth-2 accumulation, Poseidon parents.
        for (uint256 width = slots; width > 1; width /= 2) {
            for (uint256 i = 0; i < width / 2; i++) {
                leaves[i] = FairProofEncoding.hash2(leaves[2 * i], leaves[2 * i + 1]);
            }
        }
        return leaves[0];
    }

    /**
     * @dev ecrecover with the malleability guard.
     *
     *      An `s` above half the curve order gives a second valid signature
     *      for the same digest and key. It cannot forge a receipt - the
     *      recovered address is the same - but it does mean a receipt has two
     *      byte encodings, and `receiptLeaf` covers the signature bytes. Two
     *      encodings would therefore produce two different
     *      `storageReceiptRoot` values for one set of acknowledgements, and a
     *      verifier replaying the events could compute a root that does not
     *      match the chain's. Rejecting the high-`s` form keeps the root a
     *      function of the acknowledgements.
     */
    function _recover(bytes32 digest, bytes calldata signature)
        private
        pure
        returns (address)
    {
        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            return address(0);
        }
        return ecrecover(digest, v, r, s);
    }

    // ---------------------------------------------------------------- reading

    /// @notice The current accumulator root. Zero before the first bid.
    function bidSetRoot(bytes32 tenderId) external view returns (uint256) {
        IncrementalMerkleTree.Tree storage tree = _trees[tenderId];
        if (tree.depth == 0) return 0;
        return tree.getRoot();
    }

    function submissionCount(bytes32 tenderId) external view returns (uint256) {
        return _bids[tenderId].length;
    }

    function getBid(bytes32 tenderId, uint256 index) external view returns (Bid memory) {
        if (index >= _bids[tenderId].length) revert NoBids(tenderId);
        return _bids[tenderId][index];
    }

    function getBids(bytes32 tenderId) external view returns (Bid[] memory) {
        return _bids[tenderId];
    }

    /// @notice The accepted leaves in submission order, for the award witness.
    function getLeaves(bytes32 tenderId) external view returns (uint256[] memory) {
        IncrementalMerkleTree.Tree storage tree = _trees[tenderId];
        if (tree.depth == 0) return new uint256[](0);
        return tree.getLeaves();
    }

    /// @notice Remaining capacity, so a UI can warn before a bidder pays.
    function remainingCapacity(bytes32 tenderId) external view returns (uint32) {
        uint32 used = uint32(_bids[tenderId].length);
        return used >= MAX_BIDS ? 0 : MAX_BIDS - used;
    }
}
