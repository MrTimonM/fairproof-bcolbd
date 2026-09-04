// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IFairProofErrors} from "./interfaces/IFairProofErrors.sol";
import {Governance} from "./Governance.sol";
import {SealedBid} from "./SealedBid.sol";
import {TenderRegistry} from "./TenderRegistry.sol";

/**
 * @title BondEscrow
 * @notice A non-transferable record of bid-bond status. Nothing more.
 *
 * @dev Development plan Section 9.6. Whitepaper Figure 4 lists a Bond Escrow
 *      contract in the architecture, Section 6 routes the bid bond "through the
 *      escrow contract" as a metadata-linkability mitigation, and Section 13
 *      has it hold "a tokenized representation" while the bank keeps the
 *      underlying guarantee.
 *
 *      WHAT THIS IS NOT. It is not a payment rail, it holds no value, and it
 *      moves no tokens. The authoritative guarantee remains a bank instrument;
 *      this contract stores a HASH of the reference to that instrument and
 *      never the instrument itself. Anything more would be a claim the
 *      prototype cannot honour - a smart contract cannot hold a bank guarantee.
 *
 *      WHY THE BOND IS ROUTED THROUGH A CONTRACT AT ALL. A bid bond posted
 *      directly with the procuring entity links a firm to a tender before the
 *      deadline, which defeats the sealed-bid design at the one point where
 *      money has to move. Routing the status through a nullifier-keyed record
 *      means the entity learns that a bond exists for a bid without learning
 *      whose.
 *
 * @dev BOND STATUS IS NOT AN OPENING DEPENDENCY, and this is deliberate.
 *
 *      Whitepaper Table 7 is explicit: "Procurement workflow; not an opening
 *      dependency." So nothing here is consulted by OpeningManager or
 *      AwardManager, and there is no function on this contract that could
 *      block either. If bond status gated the opening, a bank adapter that
 *      failed to act - or was leaned on - could stall a tender indefinitely,
 *      which converts a procurement formality into a censorship lever.
 *
 *      That means an unposted bond is a matter for the procurement workflow to
 *      resolve, exactly as it is on paper today. The contract records what
 *      happened; it does not enforce the commercial consequence.
 */
contract BondEscrow is IFairProofErrors {
    enum Status {
        NONE,
        POSTED,
        RELEASED,
        FORFEITED
    }

    struct Bond {
        Status status;
        /// @dev keccak256 of the off-chain guarantee reference. NEVER the
        ///      instrument, and never anything that identifies the bidder.
        bytes32 guaranteeRef;
        /// @dev Declared value in BDT minor units, for the audit trail. The
        ///      bank's instrument is authoritative if the two ever disagree.
        uint256 declaredAmount;
        uint64 postedAt;
        uint64 settledAt;
        address postedBy;
        address settledBy;
        string settlementReason;
    }

    Governance public immutable governance;
    TenderRegistry public immutable tenderRegistry;
    SealedBid public immutable sealedBid;

    /// @dev Bank adapters may post and settle. Council-controlled.
    mapping(address => bool) public isBankAdapter;
    /// @dev tenderId => nullifier => bond. Keyed by NULLIFIER, not by address,
    ///      so the record carries no bidder identity.
    mapping(bytes32 => mapping(uint256 => Bond)) private _bonds;
    mapping(bytes32 => uint256) public postedCount;

    // NotBankAdapter is already declared in IFairProofErrors, which this
    // contract inherits, so it is not redeclared here.
    error BondAlreadyPosted(bytes32 tenderId, uint256 nullifier);
    error BondNotPosted(bytes32 tenderId, uint256 nullifier);
    error BondAlreadySettled(bytes32 tenderId, uint256 nullifier, Status status);
    error UnknownNullifier(bytes32 tenderId, uint256 nullifier);
    error EmptyGuaranteeRef();
    error ZeroDeclaredAmount();

    event BankAdapterSet(address indexed adapter, bool allowed, string reason);
    event BondPosted(
        bytes32 indexed tenderId,
        uint256 indexed nullifier,
        bytes32 guaranteeRef,
        uint256 declaredAmount,
        address indexed postedBy
    );
    event BondSettled(
        bytes32 indexed tenderId,
        uint256 indexed nullifier,
        Status status,
        string reason,
        address indexed settledBy
    );

    modifier onlyCouncil() {
        if (!governance.isCouncilMember(msg.sender)) revert NotCouncilMember(msg.sender);
        _;
    }

    modifier onlyBankAdapter() {
        if (!isBankAdapter[msg.sender]) revert NotBankAdapter(msg.sender);
        _;
    }

    constructor(
        Governance governance_,
        TenderRegistry tenderRegistry_,
        SealedBid sealedBid_
    ) {
        governance = governance_;
        tenderRegistry = tenderRegistry_;
        sealedBid = sealedBid_;
    }

    /// @notice Authorise a bank adapter. Council only, with a recorded reason.
    function setBankAdapter(address adapter, bool allowed, string calldata reason)
        external
        onlyCouncil
    {
        if (bytes(reason).length == 0) revert ReasonRequired();
        isBankAdapter[adapter] = allowed;
        emit BankAdapterSet(adapter, allowed, reason);
    }

    /**
     * @notice Record that a bond has been posted for an accepted bid.
     *
     * @dev The nullifier must belong to a bid the chain actually accepted.
     *      Without that check the escrow would accumulate records for bids
     *      that do not exist, and the count shown beside a tender would be
     *      meaningless.
     */
    function postBond(
        bytes32 tenderId,
        uint256 nullifier,
        bytes32 guaranteeRef,
        uint256 declaredAmount
    ) external onlyBankAdapter {
        if (guaranteeRef == bytes32(0)) revert EmptyGuaranteeRef();
        if (declaredAmount == 0) revert ZeroDeclaredAmount();
        if (!sealedBid.nullifierUsed(tenderId, nullifier)) {
            revert UnknownNullifier(tenderId, nullifier);
        }

        Bond storage b = _bonds[tenderId][nullifier];
        if (b.status != Status.NONE) revert BondAlreadyPosted(tenderId, nullifier);

        b.status = Status.POSTED;
        b.guaranteeRef = guaranteeRef;
        b.declaredAmount = declaredAmount;
        b.postedAt = uint64(block.timestamp);
        b.postedBy = msg.sender;
        postedCount[tenderId] += 1;

        emit BondPosted(tenderId, nullifier, guaranteeRef, declaredAmount, msg.sender);
    }

    /**
     * @notice Release or forfeit a posted bond.
     * @dev One-shot: a settled bond is a historical fact. Re-settling would let
     *      a forfeiture be quietly rewritten as a release, which is precisely
     *      the kind of after-the-fact edit this system exists to prevent.
     */
    function settleBond(
        bytes32 tenderId,
        uint256 nullifier,
        bool released,
        string calldata reason
    ) external onlyBankAdapter {
        if (bytes(reason).length == 0) revert ReasonRequired();
        Bond storage b = _bonds[tenderId][nullifier];
        if (b.status == Status.NONE) revert BondNotPosted(tenderId, nullifier);
        if (b.status != Status.POSTED) {
            revert BondAlreadySettled(tenderId, nullifier, b.status);
        }

        b.status = released ? Status.RELEASED : Status.FORFEITED;
        b.settledAt = uint64(block.timestamp);
        b.settledBy = msg.sender;
        b.settlementReason = reason;

        emit BondSettled(tenderId, nullifier, b.status, reason, msg.sender);
    }

    function getBond(bytes32 tenderId, uint256 nullifier)
        external
        view
        returns (Bond memory)
    {
        return _bonds[tenderId][nullifier];
    }

    function statusOf(bytes32 tenderId, uint256 nullifier) external view returns (Status) {
        return _bonds[tenderId][nullifier].status;
    }

    /**
     * @notice How many accepted bids have a posted bond.
     * @dev For the audit trail and the UI. It is NOT a precondition for
     *      anything - see the note on this contract about why gating the
     *      opening on bond status would be a censorship lever.
     */
    function bondSummary(bytes32 tenderId)
        external
        view
        returns (uint256 accepted, uint256 posted, uint256 released, uint256 forfeited)
    {
        accepted = sealedBid.submissionCount(tenderId);
        for (uint256 i = 0; i < accepted; i++) {
            SealedBid.Bid memory bid = sealedBid.getBid(tenderId, i);
            Status s = _bonds[tenderId][bid.nullifier].status;
            if (s == Status.POSTED) posted++;
            else if (s == Status.RELEASED) released++;
            else if (s == Status.FORFEITED) forfeited++;
        }
    }
}
