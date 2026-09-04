// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {FairProofEncoding} from "../lib/FairProofEncoding.sol";

/**
 * @title EncodingHarness
 * @notice Test-only wrapper exposing FairProofEncoding's internal functions.
 * @dev Never deployed to the permissioned network. It exists so the
 *      cross-language equality test (development plan Section 11A.6) can call
 *      the Solidity leg of the frozen encoding.
 */
contract EncodingHarness {
    function toField(bytes32 digest) external pure returns (uint256) {
        return FairProofEncoding.toField(digest);
    }

    function toLimbs(bytes32 hash) external pure returns (uint256, uint256) {
        return FairProofEncoding.toLimbs(hash);
    }

    function fromLimbs(uint256 hi, uint256 lo) external pure returns (bytes32) {
        return FairProofEncoding.fromLimbs(hi, lo);
    }

    function tenderIdField(string calldata id) external pure returns (uint256) {
        return FairProofEncoding.tenderIdField(id);
    }

    function hash2(uint256 a, uint256 b) external pure returns (uint256) {
        return FairProofEncoding.hash2(a, b);
    }

    function bidLeaf(
        uint256 nullifier,
        uint256 bidCommitment,
        uint256 ciphertextHashField,
        uint256 submissionIndex
    ) external pure returns (uint256) {
        return
            FairProofEncoding.bidLeaf(
                nullifier,
                bidCommitment,
                ciphertextHashField,
                submissionIndex
            );
    }

    /// @dev Empty-tree root at BID_TREE_DEPTH, built from the padding leaf.
    function emptyRoot() external pure returns (uint256) {
        uint256 node = FairProofEncoding.DOMAIN_PADDING_V1;
        for (uint256 i = 0; i < FairProofEncoding.BID_TREE_DEPTH; i++) {
            node = FairProofEncoding.hash2(node, node);
        }
        return node;
    }

    /// @dev Gas measurement for the benchmark report (plan Section 22).
    ///      `view` so the value is returned directly rather than a tx hash.
    function measureHash2Gas(uint256 a, uint256 b) external view returns (uint256) {
        uint256 before = gasleft();
        FairProofEncoding.hash2(a, b);
        return before - gasleft();
    }

    function measureBidLeafGas(
        uint256 nullifier,
        uint256 bidCommitment,
        uint256 ciphertextHashField,
        uint256 submissionIndex
    ) external view returns (uint256) {
        uint256 before = gasleft();
        FairProofEncoding.bidLeaf(
            nullifier,
            bidCommitment,
            ciphertextHashField,
            submissionIndex
        );
        return before - gasleft();
    }
}
