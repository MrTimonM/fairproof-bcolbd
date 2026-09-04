// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IncrementalMerkleTree} from "../lib/IncrementalMerkleTree.sol";
import {FairProofEncoding} from "../lib/FairProofEncoding.sol";

/**
 * @title MerkleHarness
 * @notice Test-only wrapper over IncrementalMerkleTree.
 * @dev Exists so the tree can be compared against the TypeScript accumulator
 *      leaf by leaf. If the two disagree, every award proof would fail
 *      against the chain's root.
 */
contract MerkleHarness {
    using IncrementalMerkleTree for IncrementalMerkleTree.Tree;

    IncrementalMerkleTree.Tree private _tree;

    constructor(uint8 depth) {
        _tree.init(depth);
    }

    function insert(uint256 leaf) external returns (uint32) {
        return _tree.insert(leaf);
    }

    function insertBidLeaf(
        uint256 nullifier,
        uint256 bidCommitment,
        uint256 ciphertextHashField,
        uint256 submissionIndex
    ) external returns (uint32) {
        return
            _tree.insert(
                FairProofEncoding.bidLeaf(
                    nullifier,
                    bidCommitment,
                    ciphertextHashField,
                    submissionIndex
                )
            );
    }

    function root() external view returns (uint256) {
        return _tree.getRoot();
    }

    function leafCount() external view returns (uint32) {
        return _tree.leafCount;
    }

    function capacity() external view returns (uint32) {
        return _tree.capacity();
    }

    function leaves() external view returns (uint256[] memory) {
        return _tree.getLeaves();
    }

    function measureInsertGas(uint256 leaf) external returns (uint256) {
        uint256 before = gasleft();
        _tree.insert(leaf);
        return before - gasleft();
    }
}
