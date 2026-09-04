// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IFairProofErrors} from "./interfaces/IFairProofErrors.sol";
import {Governance} from "./Governance.sol";

/**
 * @title CheckpointAnchor
 * @notice Records periodic checkpoints of the permissioned chain's state.
 *
 * @dev Development plan Section 9.8. Whitepaper Section 9.2 defines
 *
 *          checkpoint = keccak256(blockNumber, blockHash, tenderStateRoot)
 *
 *      and Section 19.4 shows an "optional public anchor" on the integrity
 *      report.
 *
 * @dev WHAT THIS DOES AND DOES NOT ACHIEVE, because the difference is the
 *      whole point of the mechanism.
 *
 *      The problem it addresses: this is a permissioned chain with four
 *      validators. If all four colluded they could in principle rewrite
 *      history wholesale, and no amount of on-chain proof would reveal it -
 *      every proof would be re-verified against the rewritten state.
 *
 *      The remedy is to publish a checkpoint somewhere the four validators do
 *      not control, so that a later rewrite contradicts a value already
 *      committed elsewhere. Whitepaper Section 19.1 is careful about how much
 *      that buys: the testnet is "a demo mirror, not a state proof", and
 *      anchoring is "production design until implemented".
 *
 *      DEPLOYED HERE, ON THE PERMISSIONED CHAIN ITSELF, THIS CONTRACT PROVIDES
 *      NO EXTERNAL GUARANTEE AT ALL. A checkpoint recorded by the same
 *      validators that could rewrite the history it describes is worth
 *      exactly nothing against that threat. It is useful for two narrower
 *      things:
 *
 *        1. It fixes the checkpoint FORMULA and makes it reproducible, so the
 *           independent verifier has something concrete to recompute.
 *        2. It gives the mirror script a source of committed checkpoints to
 *           publish, once there is a public chain to publish them to.
 *
 *      The integrity report and the verifier must therefore describe the
 *      anchor row as absent until the same checkpoint appears on a chain this
 *      project does not control. Recording that plainly is the only honest
 *      way to ship this contract.
 */
contract CheckpointAnchor is IFairProofErrors {
    struct Checkpoint {
        uint64 permissionedChainId;
        uint64 blockNumber;
        bytes32 blockHash;
        /// @dev Digest over the finalized tender state. See `computeStateRoot`.
        bytes32 tenderStateRoot;
        bytes32 checkpoint;
        uint64 recordedAt;
        address recordedBy;
        /// @dev Where the same checkpoint was published externally, if
        ///      anywhere. Empty means it was not, and the report must say so.
        string externalAnchorUri;
    }

    Governance public immutable governance;
    uint64 public immutable permissionedChainId;

    Checkpoint[] private _checkpoints;
    /**
     * @dev checkpoint digest => index + 1.
     *
     *      Its real job is to back , which is how the independent
     *      verifier confirms a checkpoint it recomputed from the permissioned
     *      chain was actually committed here. The duplicate guard below is
     *      unreachable defence-in-depth: the block number is inside the
     *      digest, so a genuine duplicate would need the same block number,
     *      which the monotonic check rejects first.
     */
    mapping(bytes32 => uint256) private _seen;

    error CheckpointAlreadyRecorded(bytes32 checkpoint);
    error BlockNotAdvanced(uint64 last, uint64 offered);
    error NoCheckpoints();
    error CheckpointNotFound(uint256 index);
    error ExternalAnchorAlreadySet(uint256 index);

    event CheckpointRecorded(
        uint256 indexed index,
        uint64 blockNumber,
        bytes32 blockHash,
        bytes32 tenderStateRoot,
        bytes32 checkpoint,
        address indexed recordedBy
    );
    event ExternalAnchorRecorded(uint256 indexed index, string uri, address indexed by);

    modifier onlyCouncil() {
        if (!governance.isCouncilMember(msg.sender)) revert NotCouncilMember(msg.sender);
        _;
    }

    constructor(Governance governance_, uint64 permissionedChainId_) {
        governance = governance_;
        permissionedChainId = permissionedChainId_;
    }

    /// @notice The whitepaper's formula, Section 9.2. Exposed so the verifier
    ///         and the mirror script compute it the same way this contract does.
    function computeCheckpoint(
        uint64 chainId,
        uint64 blockNumber,
        bytes32 blockHash,
        bytes32 tenderStateRoot
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(chainId, blockNumber, blockHash, tenderStateRoot));
    }

    /**
     * @notice Record a checkpoint.
     *
     * @dev Council-gated and monotonic in block number. `blockHash` and
     *      `tenderStateRoot` are supplied rather than read: the EVM can only
     *      see the last 256 block hashes, and the tender state root is a
     *      digest over many contracts' state that Solidity cannot assemble
     *      cheaply. That means this contract TRUSTS the submitter for those
     *      two values - which is acceptable only because the checkpoint's
     *      value comes from being republished somewhere else, and anyone can
     *      recompute it from the permissioned chain and detect a false one.
     */
    function recordCheckpoint(
        uint64 blockNumber,
        bytes32 blockHash,
        bytes32 tenderStateRoot
    ) external onlyCouncil returns (uint256 index) {
        if (_checkpoints.length > 0) {
            uint64 last = _checkpoints[_checkpoints.length - 1].blockNumber;
            if (blockNumber <= last) revert BlockNotAdvanced(last, blockNumber);
        }
        bytes32 digest = computeCheckpoint(
            permissionedChainId,
            blockNumber,
            blockHash,
            tenderStateRoot
        );
        if (_seen[digest] != 0) revert CheckpointAlreadyRecorded(digest);

        index = _checkpoints.length;
        _checkpoints.push(
            Checkpoint({
                permissionedChainId: permissionedChainId,
                blockNumber: blockNumber,
                blockHash: blockHash,
                tenderStateRoot: tenderStateRoot,
                checkpoint: digest,
                recordedAt: uint64(block.timestamp),
                recordedBy: msg.sender,
                externalAnchorUri: ""
            })
        );
        _seen[digest] = index + 1;

        emit CheckpointRecorded(
            index,
            blockNumber,
            blockHash,
            tenderStateRoot,
            digest,
            msg.sender
        );
    }

    /**
     * @notice Record where a checkpoint was published externally.
     * @dev One-shot per checkpoint. The URI is a claim, not a proof - a reader
     *      must follow it and confirm the digest matches. The integrity report
     *      must present it that way rather than as a verified anchor.
     */
    function recordExternalAnchor(uint256 index, string calldata uri) external onlyCouncil {
        if (index >= _checkpoints.length) revert CheckpointNotFound(index);
        if (bytes(uri).length == 0) revert ReasonRequired();
        if (bytes(_checkpoints[index].externalAnchorUri).length != 0) {
            revert ExternalAnchorAlreadySet(index);
        }
        _checkpoints[index].externalAnchorUri = uri;
        emit ExternalAnchorRecorded(index, uri, msg.sender);
    }

    function count() external view returns (uint256) {
        return _checkpoints.length;
    }

    function at(uint256 index) external view returns (Checkpoint memory) {
        if (index >= _checkpoints.length) revert CheckpointNotFound(index);
        return _checkpoints[index];
    }

    function latest() external view returns (Checkpoint memory) {
        if (_checkpoints.length == 0) revert NoCheckpoints();
        return _checkpoints[_checkpoints.length - 1];
    }

    /// @notice Whether a checkpoint digest has been recorded here.
    function isRecorded(bytes32 digest) external view returns (bool) {
        return _seen[digest] != 0;
    }

    /**
     * @notice How many checkpoints carry an external anchor.
     * @dev Zero means the anchor row in every integrity report must read
     *      ABSENT, not PENDING - there is nothing outside this chain's
     *      validators attesting to any of this.
     */
    function externallyAnchoredCount() external view returns (uint256 anchored) {
        for (uint256 i = 0; i < _checkpoints.length; i++) {
            if (bytes(_checkpoints[i].externalAnchorUri).length != 0) anchored++;
        }
    }
}
