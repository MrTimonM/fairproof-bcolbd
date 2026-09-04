// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IFairProofErrors} from "./interfaces/IFairProofErrors.sol";

/**
 * @title Governance
 * @notice The FairProof prototype council: 3-of-4 approval with a timelock.
 *
 * @dev Implements whitepaper Section 14 and Section 11.3 as an enforced
 *      mechanism rather than prose:
 *
 *      - "Issuer admission, verifier-version activation and validator changes
 *         require 3-of-4 approval; verifier changes also require a timelock"
 *      - "Emergency pause and cancellation require 3-of-4 and an on-chain
 *         reason"
 *      - "role changes are timelocked, so a captured governance key cannot
 *         silently grant itself powers"
 *
 *      The four council members are the Regulator, the Procuring Entity, the
 *      Independent Auditor and the Chamber (whitepaper Section 14, "Prototype
 *      council"). They are synthetic prototype roles.
 *
 * @dev THE LOAD-BEARING INVARIANT. Whitepaper Section 14 ends on this
 *      sentence: "No action rewrites an active tender's rules or verifier."
 *      This contract therefore exposes NO function that can reach an active
 *      tender's rules or its pinned verifier version. That is the difference
 *      between governance and a backdoor, and it is what makes "oversight
 *      without a rewrite pen" (Section 14) a checkable claim.
 *
 *      Cancellation is the deliberate exception and it is not a rewrite: it
 *      terminates a tender and records a reason. Whitepaper Section 14 commits
 *      to "cancellation and versioned reissue" instead of in-place amendment,
 *      so there is no deadline-extension or rule-edit action here at all.
 */
contract Governance is IFairProofErrors {
    /// @notice Actions the council may take. Deliberately a closed set.
    enum ActionType {
        RegisterIssuer,
        SetIssuerStatus,
        PublishIssuerRegistryRoot,
        ActivateVerifierVersion,
        RecordValidatorChange,
        SetTenderAuthority,
        SetCommittee,
        EmergencyPause,
        Unpause,
        CancelTender
    }

    struct Proposal {
        ActionType action;
        /// @dev ABI-encoded arguments, interpreted by the target module.
        bytes payload;
        /// @dev Mandatory on-chain justification (whitepaper Section 14).
        string reason;
        address proposer;
        uint64 proposedAt;
        /// @dev Earliest execution time; equals proposedAt when no timelock.
        uint64 executableAt;
        uint8 approvals;
        bool executed;
        bool cancelled;
    }

    /// @notice Council threshold. Whitepaper Section 14: 3-of-4.
    uint8 public constant COUNCIL_THRESHOLD = 3;
    uint8 public constant COUNCIL_SIZE = 4;

    /**
     * @notice Timelock on verifier activation and role changes.
     * @dev Whitepaper Section 14: "timelocked verifier upgrades never alter a
     *      running tender". Short here so the prototype is demonstrable; the
     *      production value is stated in the documentation, not hard-coded to
     *      a demo-friendly number and then described as production-ready.
     */
    uint64 public constant TIMELOCK_SECONDS = 60;

    address[COUNCIL_SIZE] private _council;
    mapping(address => bool) public isCouncilMember;

    uint256 public proposalCount;
    mapping(uint256 => Proposal) private _proposals;
    mapping(uint256 => mapping(address => bool)) public hasApproved;

    /// @notice Whether the protocol is paused. Whitepaper Section 14.
    bool public paused;

    event CouncilInitialised(address[COUNCIL_SIZE] members);
    event ProposalCreated(
        uint256 indexed proposalId,
        ActionType indexed action,
        address indexed proposer,
        string reason,
        uint64 executableAt
    );
    event ProposalApproved(uint256 indexed proposalId, address indexed member, uint8 approvals);
    event ProposalExecuted(uint256 indexed proposalId, ActionType indexed action, string reason);
    event Paused(uint256 indexed proposalId, string reason);
    event Unpaused(uint256 indexed proposalId, string reason);

    modifier onlyCouncil() {
        if (!isCouncilMember[msg.sender]) revert NotCouncilMember(msg.sender);
        _;
    }

    constructor(address[COUNCIL_SIZE] memory members) {
        for (uint256 i = 0; i < COUNCIL_SIZE; i++) {
            address m = members[i];
            if (m == address(0)) revert InvalidCouncilSize(i);
            if (isCouncilMember[m]) revert DuplicateCouncilMember(m);
            isCouncilMember[m] = true;
            _council[i] = m;
        }
        emit CouncilInitialised(members);
    }

    /// @notice The four council members, in registration order.
    function council() external view returns (address[COUNCIL_SIZE] memory) {
        return _council;
    }

    function getProposal(uint256 proposalId) external view returns (Proposal memory) {
        Proposal memory p = _proposals[proposalId];
        if (p.proposedAt == 0) revert ProposalNotFound(proposalId);
        return p;
    }

    /**
     * @notice Whether an action carries a timelock.
     * @dev Verifier activation and role changes are timelocked so a captured
     *      key cannot silently grant itself powers (whitepaper Section 11.3).
     *      An emergency pause is deliberately NOT timelocked: a pause that
     *      takes effect an hour later is not an emergency control.
     */
    function isTimelocked(ActionType action) public pure returns (bool) {
        return
            action == ActionType.ActivateVerifierVersion ||
            action == ActionType.SetTenderAuthority ||
            action == ActionType.SetCommittee ||
            action == ActionType.RegisterIssuer ||
            action == ActionType.SetIssuerStatus;
    }

    /**
     * @notice Propose a council action. The proposer's own approval counts.
     * @param reason Mandatory justification, recorded on-chain and emitted.
     */
    function propose(
        ActionType action,
        bytes calldata payload,
        string calldata reason
    ) external onlyCouncil returns (uint256 proposalId) {
        // Whitepaper Section 14 requires an on-chain reason for council
        // action. An empty string would satisfy the type and defeat the point.
        if (bytes(reason).length == 0) revert ReasonRequired();

        proposalId = ++proposalCount;
        uint64 nowTs = uint64(block.timestamp);
        uint64 executableAt = isTimelocked(action) ? nowTs + TIMELOCK_SECONDS : nowTs;

        Proposal storage p = _proposals[proposalId];
        p.action = action;
        p.payload = payload;
        p.reason = reason;
        p.proposer = msg.sender;
        p.proposedAt = nowTs;
        p.executableAt = executableAt;
        p.approvals = 1;

        hasApproved[proposalId][msg.sender] = true;

        emit ProposalCreated(proposalId, action, msg.sender, reason, executableAt);
        emit ProposalApproved(proposalId, msg.sender, 1);
    }

    /// @notice Approve a pending proposal. One approval per member.
    function approve(uint256 proposalId) external onlyCouncil {
        Proposal storage p = _proposals[proposalId];
        if (p.proposedAt == 0) revert ProposalNotFound(proposalId);
        if (p.executed) revert ProposalAlreadyExecuted(proposalId);
        if (hasApproved[proposalId][msg.sender]) {
            revert ProposalAlreadyApproved(proposalId, msg.sender);
        }

        hasApproved[proposalId][msg.sender] = true;
        p.approvals += 1;

        emit ProposalApproved(proposalId, msg.sender, p.approvals);
    }

    /**
     * @notice Execute an approved, timelock-elapsed proposal.
     * @dev Returns the action and payload for the caller module to apply.
     *      Only a council member may execute, so execution is attributable.
     */
    function execute(uint256 proposalId)
        external
        onlyCouncil
        returns (ActionType action, bytes memory payload)
    {
        Proposal storage p = _proposals[proposalId];
        if (p.proposedAt == 0) revert ProposalNotFound(proposalId);
        if (p.executed) revert ProposalAlreadyExecuted(proposalId);
        if (p.approvals < COUNCIL_THRESHOLD) {
            revert ThresholdNotMet(proposalId, p.approvals, COUNCIL_THRESHOLD);
        }
        if (block.timestamp < p.executableAt) {
            revert TimelockNotElapsed(proposalId, p.executableAt);
        }

        // Effects before the pause/unpause state change, so a reentrant call
        // cannot execute the same proposal twice.
        p.executed = true;

        if (p.action == ActionType.EmergencyPause) {
            if (paused) revert SystemPaused();
            paused = true;
            emit Paused(proposalId, p.reason);
        } else if (p.action == ActionType.Unpause) {
            if (!paused) revert SystemNotPaused();
            paused = false;
            emit Unpaused(proposalId, p.reason);
        }

        emit ProposalExecuted(proposalId, p.action, p.reason);
        return (p.action, p.payload);
    }

    /**
     * @notice Whether a proposal is executable right now.
     * @dev Read by the UI so it can show WHY an action is not yet available -
     *      awaiting approvals versus awaiting the timelock - rather than a
     *      disabled button with no explanation (plan Section 17.4).
     */
    function executionStatus(uint256 proposalId)
        external
        view
        returns (bool executable, uint8 approvals, uint8 required, uint64 executableAt)
    {
        Proposal storage p = _proposals[proposalId];
        if (p.proposedAt == 0) revert ProposalNotFound(proposalId);
        approvals = p.approvals;
        required = COUNCIL_THRESHOLD;
        executableAt = p.executableAt;
        executable =
            !p.executed &&
            approvals >= required &&
            block.timestamp >= executableAt;
    }
}
