// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IFairProofErrors} from "./interfaces/IFairProofErrors.sol";
import {IWinnerIdentityVerifier} from "./interfaces/IWinnerIdentityVerifier.sol";
import {FairProofEncoding} from "./lib/FairProofEncoding.sol";
import {AwardManager} from "./AwardManager.sol";
import {IssuerRegistry} from "./IssuerRegistry.sol";
import {SealedBid} from "./SealedBid.sol";
import {TenderRegistry} from "./TenderRegistry.sol";

/**
 * @title WinnerIdentity
 * @notice The ownership proof that must exist before any legal identity is
 *         displayed next to a winning bid.
 *
 * @dev Development plan Section 9.7, whitepaper Section 7. Build order
 *      step 15.
 *
 *      THE PROBLEM. After the award, the winning bid is a commitment and a
 *      nullifier with no name attached. Showing a legal identity beside it on
 *      the authority's word alone would put the entire confidentiality design
 *      at the mercy of a database edit - and the integrity report would be
 *      asserting something no reader could check.
 *
 *      So the winner proves it. The proof establishes that the party
 *      publishing the identity record holds the `subjectSecret` behind the
 *      winning nullifier, that the same secret opens the `subjectCommitment`
 *      in a credential signed by an issuer in the PUBLISHED registry, and
 *      that the record and credential id are the ones bound into the
 *      commitment the proof carries.
 *
 *      THE CONTRACT DECIDES FOUR OF THE FIVE SIGNALS. `tenderIdField`,
 *      `winnerCommitment`, `nullifier` and `issuerRegistryRoot` all come from
 *      chain state. Only `credentialId` and the record bytes come from the
 *      caller, and both are hashed into signal 3 - so a winner cannot swap
 *      the record or misstate the credential id without breaking the
 *      comparison, even though neither value is itself a proof signal.
 *
 * @dev WHAT THIS DOES NOT PROVE, and the report must say so.
 *
 *      That the declared legal name is accurate. Nothing cryptographic stops a
 *      party misdescribing itself; the record is the winner's own declaration.
 *      What bounds it is that the record carries `credentialId`, so the issuer
 *      that signed that credential - and any auditor - can confirm the
 *      declaration against the firm it actually issued to. The
 *      identity-linkage row must read "linked to the credential holder", not
 *      "legal identity verified".
 */
contract WinnerIdentity is IFairProofErrors {
    uint256 public constant PUBLIC_SIGNAL_COUNT = 5;

    /// @dev keccak256("FairProof:identityRecord:v1"). Spec Section 23.
    bytes32 internal constant RAW_IDENTITY_RECORD_V1 =
        0x57ee84a2a6b343e653337bb04cf73864645746f8b4f0ec3829e1c0493c421fc1;
    /// @dev toField(keccak256("FairProof:identity:v1")). Spec Section 23.
    uint256 internal constant DOMAIN_IDENTITY_V1 =
        350255550607654703349396198304734656087699665840881769065044796263778895484;

    /// @dev A record longer than this is a denial-of-service attempt, not a
    ///      company registration.
    uint256 public constant MAX_RECORD_BYTES = 4096;

    struct Identity {
        bool proven;
        uint64 provenAt;
        address submitter;
        uint64 credentialId;
        uint256 legalIdentityCommitment;
        /// @dev The canonical JCS record, stored so the claim is permanent and
        ///      re-hashable by anyone rather than living in an off-chain
        ///      database that could change.
        bytes record;
    }

    TenderRegistry public immutable tenderRegistry;
    IssuerRegistry public immutable issuerRegistry;
    SealedBid public immutable sealedBid;
    AwardManager public immutable awardManager;
    IWinnerIdentityVerifier public immutable verifier;
    uint32 public immutable circuitVersion;
    bytes32 public immutable vkeyHash;
    string public transcriptUri;

    mapping(bytes32 => Identity) private _identities;

    error NotAwarded(bytes32 tenderId);
    error AlreadyProven(bytes32 tenderId);
    error RecordEmpty();
    error RecordTooLong(uint256 length, uint256 max);
    error IssuerRootNotPublished(uint64 epoch);
    error VerifierVersionMismatch(uint32 tenderPins, uint32 thisEnforces);
    error IdentityProofRejected(bytes32 tenderId);
    error NoIdentity(bytes32 tenderId);

    event WinnerIdentityProven(
        bytes32 indexed tenderId,
        uint64 indexed credentialId,
        uint256 legalIdentityCommitment,
        uint256 winnerCommitment,
        uint256 nullifier,
        uint256 recordLength,
        address submitter
    );

    constructor(
        TenderRegistry tenderRegistry_,
        IssuerRegistry issuerRegistry_,
        SealedBid sealedBid_,
        AwardManager awardManager_,
        IWinnerIdentityVerifier verifier_,
        uint32 circuitVersion_,
        bytes32 vkeyHash_,
        string memory transcriptUri_
    ) {
        tenderRegistry = tenderRegistry_;
        issuerRegistry = issuerRegistry_;
        sealedBid = sealedBid_;
        awardManager = awardManager_;
        verifier = verifier_;
        circuitVersion = circuitVersion_;
        vkeyHash = vkeyHash_;
        transcriptUri = transcriptUri_;
    }

    // -------------------------------------------------------------- encoding

    /// @notice legalIdentityHash = toField(keccak256(DOMAIN || record)). Spec 23.
    function legalIdentityHash(bytes calldata record) public pure returns (uint256) {
        return FairProofEncoding.toField(
            keccak256(abi.encodePacked(RAW_IDENTITY_RECORD_V1, record))
        );
    }

    /**
     * @notice The commitment the proof must carry as public signal 3.
     *
     * @dev Two nested arity-2 Poseidon hashes rather than one arity-3, so no
     *      third Poseidon library has to be deployed. Spec Section 23 fixes
     *      the nesting order.
     *
     *      Exposed as a view function so the winner's prover computes it the
     *      same way the contract will, rather than the two agreeing by
     *      coincidence.
     */
    function identityCommitment(uint64 credentialId, bytes calldata record)
        public
        pure
        returns (uint256)
    {
        return FairProofEncoding.hash2(
            FairProofEncoding.hash2(DOMAIN_IDENTITY_V1, credentialId),
            legalIdentityHash(record)
        );
    }

    /// @notice The five signals an identity proof for this tender must carry.
    function expectedPublicSignals(
        bytes32 tenderId,
        uint64 credentialId,
        bytes calldata record
    ) public view returns (uint256[PUBLIC_SIGNAL_COUNT] memory signals) {
        TenderRegistry.Tender memory t = tenderRegistry.getTender(tenderId);
        AwardManager.Award memory a = awardManager.getAward(tenderId);
        SealedBid.Bid memory winner = sealedBid.getBid(tenderId, a.winnerSubmissionIndex);

        bytes32 root = issuerRegistry.issuerRegistryRoot(t.issuerEpoch);
        if (root == bytes32(0)) revert IssuerRootNotPublished(t.issuerEpoch);

        signals[0] = t.tenderIdField;
        signals[1] = a.winnerCommitment;
        signals[2] = winner.nullifier;
        signals[3] = identityCommitment(credentialId, record);
        // Poseidon roots are already field elements and are NOT truncated the
        // way keccak digests are (spec Section 2).
        signals[4] = uint256(root);
    }

    // --------------------------------------------------------------- proving

    /**
     * @notice Publish the winner's identity record with its ownership proof.
     *
     * @dev Permissionless in the same sense as every other proof path here:
     *      what authorises the statement is the proof, and only the holder of
     *      the winning witness can produce it.
     */
    function submitIdentityProof(
        bytes32 tenderId,
        uint64 credentialId,
        bytes calldata record,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external {
        if (!awardManager.isAwarded(tenderId)) revert NotAwarded(tenderId);
        if (_identities[tenderId].proven) revert AlreadyProven(tenderId);
        if (record.length == 0) revert RecordEmpty();
        if (record.length > MAX_RECORD_BYTES) {
            revert RecordTooLong(record.length, MAX_RECORD_BYTES);
        }

        TenderRegistry.Tender memory t = tenderRegistry.getTender(tenderId);
        if (t.verifierVersion != circuitVersion) {
            revert VerifierVersionMismatch(t.verifierVersion, circuitVersion);
        }

        uint256[PUBLIC_SIGNAL_COUNT] memory signals =
            expectedPublicSignals(tenderId, credentialId, record);
        if (!verifier.verifyProof(proofA, proofB, proofC, signals)) {
            revert IdentityProofRejected(tenderId);
        }

        _identities[tenderId] = Identity({
            proven: true,
            provenAt: uint64(block.timestamp),
            submitter: msg.sender,
            credentialId: credentialId,
            legalIdentityCommitment: signals[3],
            record: record
        });

        emit WinnerIdentityProven(
            tenderId,
            credentialId,
            signals[3],
            signals[1],
            signals[2],
            record.length,
            msg.sender
        );
    }

    // --------------------------------------------------------------- reading

    function isProven(bytes32 tenderId) external view returns (bool) {
        return _identities[tenderId].proven;
    }

    /**
     * @notice The published identity, or a revert.
     * @dev Reverting rather than returning an empty struct is deliberate: a UI
     *      that renders a blank name as "unknown bidder" beside a real award
     *      is worse than one that cannot render the panel at all.
     */
    function getIdentity(bytes32 tenderId) external view returns (Identity memory) {
        Identity memory i = _identities[tenderId];
        if (!i.proven) revert NoIdentity(tenderId);
        return i;
    }

    /// @notice The stored record, for anyone re-hashing the claim.
    function getRecord(bytes32 tenderId) external view returns (bytes memory) {
        return _identities[tenderId].record;
    }
}
