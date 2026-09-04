// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IFairProofErrors} from "./interfaces/IFairProofErrors.sol";
import {Governance} from "./Governance.sol";

/**
 * @title IssuerRegistry
 * @notice Approved qualification issuers, the registry root the circuit proves
 *         membership against, and epoch-scoped revocation roots.
 *
 * @dev Implements development plan Section 9.1 and whitepaper Section 5
 *      clauses 2 and 3, plus the close-time status requirement of Section 5.
 *
 *      Issuer keys are BabyJubjub points, not Ethereum addresses, because the
 *      credential signature is EdDSA-BabyJubjub verified inside a BN254
 *      circuit (docs/field-encoding.md Section 8).
 *
 * @dev WHY A MERKLE ROOT AND NOT A MAPPING. Whitepaper Section 5 clause 2
 *      requires the circuit to prove `issuerPubKey` is a MEMBER of
 *      `issuerRegistryRoot`. A per-issuer boolean in contract storage cannot
 *      satisfy that: a circuit cannot read contract storage. Without the root,
 *      the circuit would accept any key that produced a valid signature -
 *      which is self-attestation, exactly what clause 2 exists to prevent.
 *      An earlier draft of the development plan omitted this.
 */
contract IssuerRegistry is IFairProofErrors {
    /// @dev Issuer registry tree depth. Spec Section 15: depth 4, capacity 16.
    uint256 public constant ISSUER_TREE_DEPTH = 4;
    uint256 public constant MAX_ISSUERS = 16;

    struct Issuer {
        /// @dev BabyJubjub public key of the issuer's EdDSA signing key.
        uint256 pubKeyX;
        uint256 pubKeyY;
        /// @dev Epoch in which this key was registered.
        uint64 epoch;
        /// @dev Credential schema version this issuer may sign.
        uint32 schemaVersion;
        bool active;
        bool registered;
        string label;
    }

    Governance public immutable governance;

    mapping(bytes32 => Issuer) private _issuers;
    bytes32[] private _issuerIds;

    /// @notice Current epoch. Rolling the epoch contains a key compromise to
    ///         a bounded set of credentials (whitepaper Section 11.2).
    uint64 public currentEpoch;

    /// @notice issuerRegistryRoot per epoch. Circuit clause 2 proves against this.
    mapping(uint64 => bytes32) public issuerRegistryRoot;

    /// @notice Sparse-Merkle revocation root per epoch. Circuit clause 3.
    mapping(uint64 => bytes32) public revocationRoot;

    /**
     * @notice Revocation root pinned at a tender's close.
     * @dev Whitepaper Section 5: "At close the tender pins a deadline root,
     *      and a status proof against that root is required before award, so
     *      'unrevoked at deadline' is not inferred from an older submission
     *      snapshot." Figure 5 shows the corresponding report row.
     */
    mapping(bytes32 => bytes32) public deadlineRevocationRoot;
    mapping(bytes32 => bool) public deadlineRootPinned;

    /// @notice The only address permitted to pin a deadline root.
    address public tenderModule;

    error IssuerAlreadyRegistered(bytes32 issuerId);
    error IssuerNotRegistered(bytes32 issuerId);
    error IssuerCapacityExhausted(uint256 max);
    error InvalidIssuerKey();
    error RootNotSet(uint64 epoch);
    error DeadlineRootAlreadyPinned(bytes32 tenderId);
    error EpochMustIncrease(uint64 current, uint64 requested);
    error TenderModuleAlreadySet();
    error TenderModuleNotSet();
    error OnlyTenderModule(address caller);

    event IssuerRegistered(
        bytes32 indexed issuerId,
        uint256 pubKeyX,
        uint256 pubKeyY,
        uint64 epoch,
        string label
    );
    event IssuerStatusChanged(bytes32 indexed issuerId, bool active, string reason);
    event IssuerRegistryRootPublished(uint64 indexed epoch, bytes32 root);
    event RevocationRootPublished(uint64 indexed epoch, bytes32 root);
    event EpochRolled(uint64 indexed fromEpoch, uint64 indexed toEpoch, string reason);
    event DeadlineRevocationRootPinned(
        bytes32 indexed tenderId,
        uint64 indexed epoch,
        bytes32 root
    );

    /**
     * @dev Every mutating function is council-gated. Whitepaper Section 14:
     *      "Issuers need accreditation ... plus a governance-board vote."
     *      The registry deliberately has no owner and no admin key.
     */
    modifier onlyCouncil() {
        if (!governance.isCouncilMember(msg.sender)) revert NotCouncilMember(msg.sender);
        _;
    }

    modifier notPaused() {
        if (governance.paused()) revert SystemPaused();
        _;
    }

    constructor(Governance governance_) {
        governance = governance_;
        currentEpoch = 1;
    }

    // ---------------------------------------------------------------- issuers

    /**
     * @notice Register an approved issuer's BabyJubjub signing key.
     * @dev Council-gated and timelocked (Governance.isTimelocked).
     */
    function registerIssuer(
        bytes32 issuerId,
        uint256 pubKeyX,
        uint256 pubKeyY,
        uint32 schemaVersion,
        string calldata label
    ) external onlyCouncil notPaused {
        if (_issuers[issuerId].registered) revert IssuerAlreadyRegistered(issuerId);
        if (_issuerIds.length >= MAX_ISSUERS) revert IssuerCapacityExhausted(MAX_ISSUERS);
        // A zero point is not on the curve and would let an unregistered key
        // masquerade as a default entry.
        if (pubKeyX == 0 && pubKeyY == 0) revert InvalidIssuerKey();

        _issuers[issuerId] = Issuer({
            pubKeyX: pubKeyX,
            pubKeyY: pubKeyY,
            epoch: currentEpoch,
            schemaVersion: schemaVersion,
            active: true,
            registered: true,
            label: label
        });
        _issuerIds.push(issuerId);

        emit IssuerRegistered(issuerId, pubKeyX, pubKeyY, currentEpoch, label);
    }

    /// @notice Activate or deactivate a registered issuer, with a reason.
    function setIssuerStatus(
        bytes32 issuerId,
        bool active,
        string calldata reason
    ) external onlyCouncil {
        if (!_issuers[issuerId].registered) revert IssuerNotRegistered(issuerId);
        if (bytes(reason).length == 0) revert ReasonRequired();
        _issuers[issuerId].active = active;
        emit IssuerStatusChanged(issuerId, active, reason);
    }

    function getIssuer(bytes32 issuerId) external view returns (Issuer memory) {
        if (!_issuers[issuerId].registered) revert IssuerNotRegistered(issuerId);
        return _issuers[issuerId];
    }

    function isIssuerActive(bytes32 issuerId) external view returns (bool) {
        Issuer storage i = _issuers[issuerId];
        return i.registered && i.active;
    }

    function issuerCount() external view returns (uint256) {
        return _issuerIds.length;
    }

    function issuerIdAt(uint256 index) external view returns (bytes32) {
        return _issuerIds[index];
    }

    // ------------------------------------------------------------------ roots

    /**
     * @notice Publish the issuer registry root for an epoch.
     * @dev The root is computed off-chain over the active issuers' keys and
     *      published here. Computing a Poseidon Merkle root over 16 leaves
     *      on-chain would cost ~500k gas per publication for a value that is
     *      only ever consumed by a circuit, so it is published and then
     *      verified against the enumerable issuer list off-chain and by the
     *      independent verifier (plan Section 16.6).
     */
    function publishIssuerRegistryRoot(uint64 epoch, bytes32 root)
        external
        onlyCouncil
        notPaused
    {
        issuerRegistryRoot[epoch] = root;
        emit IssuerRegistryRootPublished(epoch, root);
    }

    /// @notice Publish the sparse-Merkle revocation root for an epoch.
    function publishRevocationRoot(uint64 epoch, bytes32 root)
        external
        onlyCouncil
        notPaused
    {
        revocationRoot[epoch] = root;
        emit RevocationRootPublished(epoch, root);
    }

    /**
     * @notice Roll the epoch forward.
     * @dev Whitepaper Section 11.2: "because each credential references an
     *      issuer epoch, a key compromise is contained to one epoch instead
     *      of requiring the revocation of every credential the issuer ever
     *      signed." Rolling forward never rewrites history - past epochs'
     *      roots remain readable, which is what makes the audit trail
     *      replayable.
     */
    function rollEpoch(uint64 newEpoch, string calldata reason) external onlyCouncil {
        if (newEpoch <= currentEpoch) revert EpochMustIncrease(currentEpoch, newEpoch);
        if (bytes(reason).length == 0) revert ReasonRequired();
        uint64 from = currentEpoch;
        currentEpoch = newEpoch;
        emit EpochRolled(from, newEpoch, reason);
    }

    /**
     * @notice Pin the current revocation root as a tender's deadline root.
     *
     * @dev Called by TenderRegistry on the transition to CLOSED. Whitepaper
     *      Section 5 requires a status proof against THIS root before award,
     *      so that "unrevoked at deadline" is not inferred from an older
     *      submission snapshot.
     *
     *      Pinning is one-shot: re-pinning would let a later revocation be
     *      retroactively hidden or introduced, which is precisely the
     *      manipulation the deadline root exists to prevent.
     */
    function pinDeadlineRevocationRoot(bytes32 tenderId) external returns (bytes32 root) {
        // Only the wired tender module may pin, so the root always
        // corresponds to a real CLOSED transition rather than an arbitrary
        // call at a moment of someone's choosing.
        if (tenderModule == address(0)) revert TenderModuleNotSet();
        if (msg.sender != tenderModule) revert OnlyTenderModule(msg.sender);
        if (deadlineRootPinned[tenderId]) revert DeadlineRootAlreadyPinned(tenderId);

        root = revocationRoot[currentEpoch];
        if (root == bytes32(0)) revert RootNotSet(currentEpoch);

        deadlineRevocationRoot[tenderId] = root;
        deadlineRootPinned[tenderId] = true;
        emit DeadlineRevocationRootPinned(tenderId, currentEpoch, root);
    }

    // ------------------------------------------------------------ wiring

    /**
     * @notice Wire the tender module once, at deployment.
     * @dev One-shot rather than a settable admin pointer: a re-settable module
     *      address would let a captured council key redirect deadline-root
     *      pinning to a contract of its choosing.
     */
    function setTenderModule(address module) external onlyCouncil {
        if (tenderModule != address(0)) revert TenderModuleAlreadySet();
        tenderModule = module;
    }
}
