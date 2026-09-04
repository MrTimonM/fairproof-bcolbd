// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/**
 * @title IFairProofErrors
 * @notice Shared custom errors.
 *
 * @dev Custom errors rather than revert strings: they are cheaper, and more
 *      importantly the UI must name the exact reason a security rule rejected
 *      an action (development plan Section 19). "Transaction failed" is not an
 *      acceptable user-facing outcome for a deliberate rejection - the whole
 *      demonstration rests on failures being legible.
 */
interface IFairProofErrors {
    // --- authorisation ---
    error NotCouncilMember(address caller);
    error NotAuthority(address caller);
    error NotIssuer(address caller);
    error NotCommitteeMember(address caller);
    error NotBankAdapter(address caller);
    error NotGovernance(address caller);

    // --- governance ---
    error ProposalNotFound(uint256 proposalId);
    error ProposalAlreadyExecuted(uint256 proposalId);
    error ProposalAlreadyApproved(uint256 proposalId, address member);
    error ThresholdNotMet(uint256 proposalId, uint8 approvals, uint8 required);
    error TimelockNotElapsed(uint256 proposalId, uint64 executableAt);
    error ReasonRequired();
    error DuplicateCouncilMember(address member);
    error InvalidCouncilSize(uint256 size);

    // --- tender lifecycle ---
    error TenderNotFound(bytes32 tenderId);
    error TenderAlreadyExists(bytes32 tenderId);
    error WrongTenderState(bytes32 tenderId, uint8 actual, uint8 expected);
    error RulesFrozen(bytes32 tenderId);
    error RulesHashMismatch(bytes32 expected, bytes32 actual);
    error ReviewWindowTooShort(uint64 biddingStart, uint64 earliest);
    error InvalidBiddingWindow(uint64 biddingStart, uint64 deadline);
    error DeadlineNotReached(uint64 deadline, uint64 now_);
    error DeadlinePassed(uint64 deadline, uint64 now_);

    // --- paused ---
    error SystemPaused();
    error SystemNotPaused();
}
