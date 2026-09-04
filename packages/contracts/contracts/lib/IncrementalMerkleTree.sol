// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {FairProofEncoding} from "./FairProofEncoding.sol";

/**
 * @title IncrementalMerkleTree
 * @notice Fixed-depth append-only Poseidon Merkle tree, matching
 *         packages/crypto/src/merkle.ts and the award circuit exactly.
 *
 * @dev docs/field-encoding.md Section 12.
 *
 *      THIS IS THE BASIS OF THE COMPLETENESS CLAIM. Whitepaper Section 7:
 *      "bidSetRoot is accumulated by the contract, not supplied by the
 *      authority, so a proof computed over a smaller set, such as one with an
 *      inconvenient low bid removed, will not verify against the root the
 *      chain already holds."
 *
 *      An append costs `depth` Poseidon hashes rather than a full rebuild,
 *      using the standard filled-subtree technique. Measured at ~34k gas per
 *      hash (docs/stage0-evidence.md), so an append at depth 5 is ~170k plus
 *      the leaf hash.
 *
 *      The empty-subtree value at level 0 is DOMAIN_PADDING_V1, NOT zero. A
 *      zero leaf would be indistinguishable from an empty subtree, which
 *      would let a real leaf be swapped for an apparently-empty slot without
 *      changing the root.
 */
library IncrementalMerkleTree {
    struct Tree {
        uint8 depth;
        uint32 leafCount;
        /// @dev Left-hand sibling cached per level, the classic incremental trick.
        mapping(uint8 => uint256) filledSubtree;
        /// @dev Precomputed empty-subtree hash per level.
        mapping(uint8 => uint256) zeros;
        /// @dev Current root.
        uint256 root;
        bool initialised;
        /// @dev Ordered leaves, so the full set is reproducible on-chain and
        ///      the award witness can be rebuilt by anyone from state alone.
        uint256[] leaves;
    }

    error AlreadyInitialised();
    error NotInitialised();
    error CapacityExhausted(uint32 leafCount, uint32 capacity);
    error DepthOutOfRange(uint8 depth);

    /// @notice Precompute the empty-subtree hashes and the empty root.
    function init(Tree storage self, uint8 depth) internal {
        if (self.initialised) revert AlreadyInitialised();
        if (depth == 0 || depth > 32) revert DepthOutOfRange(depth);

        uint256 zero = FairProofEncoding.DOMAIN_PADDING_V1;
        for (uint8 i = 0; i < depth; i++) {
            self.zeros[i] = zero;
            self.filledSubtree[i] = zero;
            zero = FairProofEncoding.hash2(zero, zero);
        }
        // After the loop, `zero` is the root of a fully empty tree.
        self.root = zero;
        self.depth = depth;
        self.initialised = true;
    }

    function capacity(Tree storage self) internal view returns (uint32) {
        return uint32(1) << self.depth;
    }

    /**
     * @notice Append a leaf and return its index.
     * @dev Reverts at capacity. Whitepaper Section 7: "Capacity exhaustion
     *      rejects further bids before acceptance", so the caller must not
     *      treat a full tree as a soft condition.
     */
    function insert(Tree storage self, uint256 leaf) internal returns (uint32 index) {
        if (!self.initialised) revert NotInitialised();
        uint32 cap = capacity(self);
        if (self.leafCount >= cap) revert CapacityExhausted(self.leafCount, cap);

        index = self.leafCount;
        uint32 position = index;
        uint256 current = leaf;

        for (uint8 level = 0; level < self.depth; level++) {
            if (position % 2 == 0) {
                // Left child: cache it and pair with the empty subtree. The
                // right sibling is not known yet.
                self.filledSubtree[level] = current;
                current = FairProofEncoding.hash2(current, self.zeros[level]);
            } else {
                // Right child: pair with the cached left sibling.
                current = FairProofEncoding.hash2(self.filledSubtree[level], current);
            }
            position /= 2;
        }

        self.root = current;
        self.leafCount = index + 1;
        self.leaves.push(leaf);
    }

    function getRoot(Tree storage self) internal view returns (uint256) {
        return self.root;
    }

    function getLeaves(Tree storage self) internal view returns (uint256[] memory) {
        return self.leaves;
    }

    function leafAt(Tree storage self, uint32 index) internal view returns (uint256) {
        return self.leaves[index];
    }
}
