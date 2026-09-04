// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IFairProofErrors} from "./interfaces/IFairProofErrors.sol";
import {IGroth16Verifier} from "./interfaces/IGroth16Verifier.sol";
import {FairProofEncoding} from "./lib/FairProofEncoding.sol";
import {Governance} from "./Governance.sol";
import {IssuerRegistry} from "./IssuerRegistry.sol";
import {TenderRegistry} from "./TenderRegistry.sol";

/**
 * @title EligibilityVerifier
 * @notice The adapter between a Groth16 proof and a tender's frozen rules.
 *
 * @dev Development plan Sections 11B.3 and 25.1 step 8.
 *
 *      The generated verifier proves one thing: that somebody knows a witness
 *      satisfying the circuit for SOME assignment of the twelve public
 *      signals. It has no idea what a tender is. Everything that makes the
 *      proof mean "this bidder meets THIS tender's published requirements"
 *      happens here, and it all reduces to one rule:
 *
 *          THE CONTRACT DECIDES THE PUBLIC SIGNALS, NOT THE CALLER.
 *
 *      A verifier adapter that accepts a caller-supplied signal array and
 *      checks a subset of it is the classic way this construction fails. The
 *      proof verifies, every signature is valid, the test suite is green -
 *      and the bidder proved eligibility against a turnover threshold of one
 *      taka that they chose themselves. So `verifyEligibility` takes only the
 *      tender id, the nullifier and the bid commitment, and reads the other
 *      ten signals out of storage.
 *
 *      `verifyWithSignals` exists for replay: a mirror or the independent
 *      verifier re-checks a proof against the signals as published in an
 *      award record. That path DOES receive an array, so it validates every
 *      element against storage before verifying - including reconstructing
 *      `rulesHash` from its two limbs (docs/field-encoding.md Section 4:
 *      "the contract must never accept limbs it did not itself derive from
 *      stored state").
 *
 * @dev VERSION PINNING. Whitepaper Section 14: "timelocked verifier upgrades
 *      never alter a running tender." Each tender freezes a `verifierVersion`
 *      inside its fields digest at activation, and this contract keeps one
 *      immutable verifier per version. Registering version N+1 cannot touch a
 *      tender pinned to N, because the lookup is by the tender's own pin and
 *      records are never overwritten. There is deliberately no default and no
 *      fallback: an unregistered version reverts rather than resolving to
 *      "the latest", which is how a verifier mismatch would otherwise fail
 *      silently.
 *
 * @dev WHY REGISTRATION CONSUMES A GOVERNANCE PROPOSAL. The other modules are
 *      gated with `onlyCouncil`, which enforces the 3-of-4 threshold but not
 *      the timelock, because `Governance.execute` hands the payload back to
 *      its caller rather than performing the call itself. For verifier
 *      activation the timelock is the point - it is the window in which the
 *      public can inspect the new verifier before it can accept proofs - so
 *      registration here requires an executed `ActivateVerifierVersion`
 *      proposal whose payload hashes to exactly the arguments supplied. The
 *      parameters are therefore fixed at proposal time, public for the whole
 *      timelock, and a proposal can be spent only once.
 */
contract EligibilityVerifier is IFairProofErrors {
    /// @notice Public signals in the eligibility circuit. Encoding spec S.16.
    uint256 public constant PUBLIC_SIGNAL_COUNT = 12;

    /**
     * @notice One immutable verifier per circuit version.
     * @dev `vkeyHash` and `sourceHash` are recorded so an outside reviewer can
     *      tie the deployed bytecode to a specific ceremony transcript. They
     *      are evidence, not enforcement: the contract cannot hash its own
     *      constants, so `ceremony:verify` is what checks them.
     */
    struct VerifierRecord {
        IGroth16Verifier impl;
        /// @dev sha256 of the canonical verification-key JSON.
        bytes32 vkeyHash;
        /// @dev sha256 of the generated Solidity source that was deployed.
        bytes32 sourceHash;
        /// @dev Where the ceremony transcript for this version is published.
        string transcriptUri;
        uint64 registeredAt;
        uint256 proposalId;
    }

    Governance public immutable governance;
    IssuerRegistry public immutable issuerRegistry;
    TenderRegistry public immutable tenderRegistry;

    mapping(uint32 => VerifierRecord) private _versions;
    uint32[] private _registeredVersions;
    /// @dev A governance proposal authorises exactly one registration.
    mapping(uint256 => bool) public proposalConsumed;

    error VerifierVersionNotRegistered(uint32 version);
    error VerifierVersionImmutable(uint32 version);
    error VerifierAddressZero();
    error WrongProposalAction(uint256 proposalId, Governance.ActionType action);
    error ProposalNotExecuted(uint256 proposalId);
    error ProposalPayloadMismatch(uint256 proposalId);
    error ProposalAlreadyConsumed(uint256 proposalId);
    error SampleProofRejected(uint32 version);
    error TenderNotActivated(bytes32 tenderId);
    error IssuerRootNotPublished(uint64 epoch);
    error RevocationRootNotPublished(uint64 epoch);
    error DeadlineRootNotPinned(bytes32 tenderId);
    error RulesHashMismatchInSignals(bytes32 expected, bytes32 fromSignals);
    error PublicSignalMismatch(uint8 index, uint256 expected, uint256 supplied);
    error ProofRejected(bytes32 tenderId, uint32 version);

    event VerifierVersionRegistered(
        uint32 indexed version,
        address indexed impl,
        bytes32 vkeyHash,
        bytes32 sourceHash,
        string transcriptUri,
        uint256 proposalId
    );

    constructor(
        Governance governance_,
        IssuerRegistry issuerRegistry_,
        TenderRegistry tenderRegistry_
    ) {
        governance = governance_;
        issuerRegistry = issuerRegistry_;
        tenderRegistry = tenderRegistry_;
    }

    // ------------------------------------------------------------- versioning

    /**
     * @notice The arguments a registration fixes at proposal time.
     * @dev Grouped into a struct because eleven parameters exceed the EVM
     *      stack depth, and `viaIR` is not available here: it inflates the
     *      linked Poseidon libraries past the EIP-170 size limit
     *      (docs/stage0-evidence.md). Same constraint as
     *      `TenderRegistry.RuleFields`.
     */
    struct Registration {
        uint32 version;
        IGroth16Verifier impl;
        /// @dev sha256 of the canonical verification-key JSON.
        bytes32 vkeyHash;
        /// @dev sha256 of the generated Solidity source that was deployed.
        bytes32 sourceHash;
        string transcriptUri;
    }

    /// @notice A proof the registered verifier must accept. See `registerVerifier`.
    struct SampleProof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
        uint256[PUBLIC_SIGNAL_COUNT] signals;
    }

    /**
     * @notice Register the verifier for a circuit version. Never overwrites.
     *
     * @param proposalId An executed `ActivateVerifierVersion` proposal whose
     *        payload equals `encodeActivationPayload(r)`.
     * @param r The verifier being activated.
     * @param sample A proof that `r.impl` must accept.
     *
     * @dev The sample proof is a liveness check with real teeth. Without it,
     *      the council can register an address that is not a verifier at all -
     *      an EOA, a self-destructed contract, a verifier for the wrong
     *      circuit - and nothing surfaces until the first bidder's submission
     *      reverts, at which point every tender pinned to that version is
     *      already frozen and unbiddable. It cannot make a dishonest verifier
     *      look honest; it only proves the registered address really verifies
     *      proofs of this shape.
     */
    function registerVerifier(
        uint256 proposalId,
        Registration calldata r,
        SampleProof calldata sample
    ) external {
        if (!governance.isCouncilMember(msg.sender)) revert NotCouncilMember(msg.sender);
        if (address(r.impl) == address(0)) revert VerifierAddressZero();
        if (address(_versions[r.version].impl) != address(0)) {
            revert VerifierVersionImmutable(r.version);
        }

        _consumeProposal(proposalId, keccak256(_payload(r)));

        if (!r.impl.verifyProof(sample.a, sample.b, sample.c, sample.signals)) {
            revert SampleProofRejected(r.version);
        }

        _versions[r.version] = VerifierRecord({
            impl: r.impl,
            vkeyHash: r.vkeyHash,
            sourceHash: r.sourceHash,
            transcriptUri: r.transcriptUri,
            registeredAt: uint64(block.timestamp),
            proposalId: proposalId
        });
        _registeredVersions.push(r.version);

        emit VerifierVersionRegistered(
            r.version,
            address(r.impl),
            r.vkeyHash,
            r.sourceHash,
            r.transcriptUri,
            proposalId
        );
    }

    /**
     * @dev Bind a registration to a specific executed proposal.
     *      `Governance.execute` already enforces 3-of-4 and the timelock and
     *      sets `executed`; this checks the action type, that the payload is
     *      byte-identical to the arguments, and that the proposal has not
     *      already been spent.
     */
    function _consumeProposal(uint256 proposalId, bytes32 expectedPayloadHash) private {
        if (proposalConsumed[proposalId]) revert ProposalAlreadyConsumed(proposalId);
        Governance.Proposal memory p = governance.getProposal(proposalId);
        if (!p.executed) revert ProposalNotExecuted(proposalId);
        if (p.action != Governance.ActionType.ActivateVerifierVersion) {
            revert WrongProposalAction(proposalId, p.action);
        }
        if (keccak256(p.payload) != expectedPayloadHash) {
            revert ProposalPayloadMismatch(proposalId);
        }
        proposalConsumed[proposalId] = true;
    }

    /// @dev The one definition of the activation payload. Both the council's
    ///      encoder and the registration check call it, so they cannot drift.
    function _payload(Registration calldata r) private pure returns (bytes memory) {
        return abi.encode(r.version, r.impl, r.vkeyHash, r.sourceHash, r.transcriptUri);
    }

    /// @notice The payload a proposal must carry for a given registration.
    /// @dev Exposed so the council can compute it on-chain rather than
    ///      trusting a script to encode it the same way.
    function encodeActivationPayload(Registration calldata r)
        external
        pure
        returns (bytes memory)
    {
        return _payload(r);
    }

    function isVersionRegistered(uint32 version) external view returns (bool) {
        return address(_versions[version].impl) != address(0);
    }

    function getVerifier(uint32 version) external view returns (VerifierRecord memory) {
        VerifierRecord memory r = _versions[version];
        if (address(r.impl) == address(0)) revert VerifierVersionNotRegistered(version);
        return r;
    }

    function registeredVersions() external view returns (uint32[] memory) {
        return _registeredVersions;
    }

    // --------------------------------------------------------- public signals

    /**
     * @notice The exact twelve signals a proof for this tender must carry.
     *
     * @dev Published as a view function on purpose. The bidder's prover needs
     *      these values, and every one of them has to come from the chain
     *      rather than from the procuring entity's website, or the authority
     *      could hand different bidders different thresholds and the proofs
     *      would all verify. This is also what the independent verifier reads
     *      to reproduce the check.
     *
     *      Ten of the twelve are derived from frozen tender state; only the
     *      nullifier and the bid commitment come from the bidder, and both are
     *      commitments that reveal nothing.
     */
    function expectedPublicSignals(
        bytes32 tenderId,
        uint256 nullifier,
        uint256 bidCommitment
    ) public view returns (uint256[PUBLIC_SIGNAL_COUNT] memory signals) {
        TenderRegistry.Tender memory t = tenderRegistry.getTender(tenderId);

        // Before activation the rules are not frozen, so there is nothing
        // meaningful to prove against; a proof bound to draft rules would be
        // invalidated by the next edit.
        if (t.activatedAt == 0) revert TenderNotActivated(tenderId);

        bytes32 issuerRoot = issuerRegistry.issuerRegistryRoot(t.issuerEpoch);
        if (issuerRoot == bytes32(0)) revert IssuerRootNotPublished(t.issuerEpoch);
        bytes32 revRoot = issuerRegistry.revocationRoot(t.issuerEpoch);
        // An empty sparse revocation tree has a non-zero root, so zero here
        // means "never published", not "nothing revoked". Accepting it would
        // let a proof be checked against a root nobody committed to.
        if (revRoot == bytes32(0)) revert RevocationRootNotPublished(t.issuerEpoch);

        (uint256 hi, uint256 lo) = FairProofEncoding.toLimbs(t.rulesHash);

        signals[0] = t.tenderIdField;
        signals[1] = hi;
        signals[2] = lo;
        signals[3] = t.requirements.turnoverThreshold;
        signals[4] = t.requirements.experienceMonths;
        signals[5] = t.requirements.certificationCode;
        signals[6] = t.deadline;
        // Poseidon roots are already field elements; they are stored in a
        // bytes32 for uniformity and are NOT truncated the way keccak digests
        // are (docs/field-encoding.md Section 2).
        signals[7] = uint256(issuerRoot);
        signals[8] = uint256(revRoot);
        signals[9] = t.issuerEpoch;
        signals[10] = nullifier;
        signals[11] = bidCommitment;
    }

    // ------------------------------------------------- close-time status

    /**
     * @notice The signals a CLOSE-TIME STATUS proof must carry.
     *
     * @dev Whitepaper Section 5: "At close the tender pins a deadline root,
     *      and a status proof against that root is required before award, so
     *      'unrevoked at deadline' is not inferred from an older submission
     *      snapshot."
     *
     *      Identical to `expectedPublicSignals` except for signal 8, which is
     *      the tender's PINNED `deadlineRevocationRoot` rather than the
     *      epoch's live one.
     *
     *      WHY THIS NEEDS NO NEW CIRCUIT. A status proof could have been a
     *      small dedicated circuit proving only non-revocation - but a bidder
     *      would then be free to pick any unrevoked `credentialId`, so the
     *      circuit would also have to carry the credential, the issuer
     *      signature and the registry membership. That is most of the
     *      eligibility circuit again, for a weaker statement.
     *
     *      Substituting the root instead re-proves the WHOLE eligibility
     *      statement evaluated at the deadline: same credential, same issuer,
     *      same thresholds, same nullifier and bid commitment, with
     *      non-revocation checked against the pinned root. It is strictly
     *      stronger than bare non-revocation, it reuses a circuit that has
     *      already been through a published ceremony, and it needs no second
     *      trusted setup.
     */
    function expectedDeadlineStatusSignals(
        bytes32 tenderId,
        uint256 nullifier,
        uint256 bidCommitment
    ) public view returns (uint256[PUBLIC_SIGNAL_COUNT] memory signals) {
        signals = expectedPublicSignals(tenderId, nullifier, bidCommitment);

        bytes32 pinned = issuerRegistry.deadlineRevocationRoot(tenderId);
        // Zero means the tender has not closed yet, so there is no deadline
        // root to prove against. An empty sparse revocation tree has a
        // NON-zero root, so zero here is never "nothing revoked".
        if (pinned == bytes32(0)) revert DeadlineRootNotPinned(tenderId);
        signals[8] = uint256(pinned);
    }

    /**
     * @notice Verify a close-time status proof.
     * @dev Same verifier, same pinned version, different root. Returns a bool
     *      for symmetry with `verifyEligibility`; `DeadlineStatus` is the
     *      contract that acts on it.
     */
    function verifyDeadlineStatus(
        bytes32 tenderId,
        uint256 nullifier,
        uint256 bidCommitment,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external view returns (bool) {
        uint256[PUBLIC_SIGNAL_COUNT] memory signals =
            expectedDeadlineStatusSignals(tenderId, nullifier, bidCommitment);
        return _verify(tenderId, signals, proofA, proofB, proofC);
    }

    // ---------------------------------------------------------- verification

    /**
     * @notice Verify an eligibility proof against a tender's frozen rules.
     * @return true only if the proof verifies under the tender's pinned
     *         verifier version against contract-derived public signals.
     */
    function verifyEligibility(
        bytes32 tenderId,
        uint256 nullifier,
        uint256 bidCommitment,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) public view returns (bool) {
        uint256[PUBLIC_SIGNAL_COUNT] memory signals =
            expectedPublicSignals(tenderId, nullifier, bidCommitment);
        return _verify(tenderId, signals, proofA, proofB, proofC);
    }

    /// @notice `verifyEligibility`, reverting instead of returning false.
    /// @dev The form call sites should use: a bool that nobody checks is how
    ///      an unverified proof gets accepted.
    function requireEligibility(
        bytes32 tenderId,
        uint256 nullifier,
        uint256 bidCommitment,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external view {
        if (!verifyEligibility(tenderId, nullifier, bidCommitment, proofA, proofB, proofC)) {
            revert ProofRejected(
                tenderId,
                tenderRegistry.getTender(tenderId).verifierVersion
            );
        }
    }

    /**
     * @notice Replay path: verify a proof against a PUBLISHED signal array.
     *
     * @dev Used when re-checking a record rather than accepting a new bid: the
     *      caller has twelve signals from an award statement or a mirror and
     *      wants the chain's own verdict on them. Every element is compared
     *      against contract-derived state first, so this is not a weaker
     *      entry point - it is the same check plus an equality proof that the
     *      published array is the one the contract would have built.
     *
     *      `rulesHash` is handled specially: the two limbs are reconstructed
     *      into a 32-byte value and compared to the stored hash, so a limb
     *      pair that is individually in range but jointly wrong is rejected
     *      with a message naming the actual hash rather than a limb index.
     */
    function verifyWithSignals(
        bytes32 tenderId,
        uint256[PUBLIC_SIGNAL_COUNT] calldata supplied,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external view returns (bool) {
        uint256[PUBLIC_SIGNAL_COUNT] memory expected =
            expectedPublicSignals(tenderId, supplied[10], supplied[11]);

        bytes32 reconstructed = FairProofEncoding.fromLimbs(supplied[1], supplied[2]);
        bytes32 stored = tenderRegistry.getTender(tenderId).rulesHash;
        if (reconstructed != stored) {
            revert RulesHashMismatchInSignals(stored, reconstructed);
        }

        for (uint8 i = 0; i < PUBLIC_SIGNAL_COUNT; i++) {
            if (supplied[i] != expected[i]) {
                revert PublicSignalMismatch(i, expected[i], supplied[i]);
            }
        }
        return _verify(tenderId, expected, proofA, proofB, proofC);
    }

    /**
     * @dev The single place a Groth16 proof is checked.
     *
     *      Both public entry points funnel through here so the version lookup
     *      and the return-value check cannot diverge between them.
     */
    function _verify(
        bytes32 tenderId,
        uint256[PUBLIC_SIGNAL_COUNT] memory signals,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) private view returns (bool) {
        uint32 version = tenderRegistry.getTender(tenderId).verifierVersion;
        IGroth16Verifier impl = _versions[version].impl;
        // No fallback to a default or to the newest version. A tender pinned
        // to a version that is not registered must fail loudly.
        if (address(impl) == address(0)) revert VerifierVersionNotRegistered(version);
        return impl.verifyProof(proofA, proofB, proofC, signals);
    }
}
