// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {PoseidonT6} from "poseidon-solidity/PoseidonT6.sol";

/**
 * @title FairProofEncoding
 * @notice The Solidity leg of docs/field-encoding.md.
 *
 * @dev Only two Poseidon arities are needed on-chain:
 *
 *   - arity 2 (PoseidonT3) for Merkle parents
 *   - arity 5 (PoseidonT6) for the bid leaf
 *
 * `credDigest`, `nullifier`, `bidCommitment` and `subjectCommitment` are
 * deliberately NOT computed here. They arrive as Groth16 public signals, so
 * the contract compares them rather than recomputing them - which is why the
 * contract never needs an arity-6 Poseidon and never touches a credential
 * field. This is a privacy property, not just an optimisation.
 *
 * Agreement with packages/crypto and packages/circuits is enforced by the
 * cross-language equality test (development plan Section 11A.6).
 */
library FairProofEncoding {
    /// @dev toField(keccak256("FairProof:leaf:v1")). Spec Section 3.
    uint256 internal constant DOMAIN_LEAF_V1 =
        190845489973463437363397010865843301780418146225117113041917773882994065432;

    /**
     * @dev toField(keccak256("FairProof:padding:v1")). Spec Section 3.
     *
     * The empty/padding leaf. NOT zero: a zero leaf is indistinguishable from
     * an empty subtree and would permit a completeness bypass in the award
     * proof (whitepaper Section 7).
     */
    uint256 internal constant DOMAIN_PADDING_V1 =
        118794039896364772078121437224410514784736280784934280083252483328023231778;

    /// @dev keccak256("FairProof:tenderId:v1"), raw. Spec Section 3.
    bytes32 internal constant RAW_TENDER_ID_V1 =
        0x9eaa6dde8d74874da28e947eb1fe707365b7288bc291b6388e5a176d0b3719ac;

    /// @dev Whitepaper Section 7: the award circuit supports MAX_BIDS = 32.
    uint256 internal constant MAX_BIDS = 32;
    uint256 internal constant BID_TREE_DEPTH = 5;

    error ValueExceeds248Bits();
    error LimbExceeds128Bits();

    /**
     * @notice Truncate a 256-bit digest to a field element. Spec Section 2.
     * @dev Right shift by 8, keeping the high 248 bits. NOT `mod p`:
     *      modular reduction would let distinct digests collide in a way an
     *      attacker can search, invisibly in the witness.
     */
    function toField(bytes32 digest) internal pure returns (uint256) {
        return uint256(digest) >> 8;
    }

    /**
     * @notice Reconstruct a 32-byte hash from two 128-bit limbs. Spec Section 4.
     * @dev The verifier adapter uses this to rebuild `rulesHash` from the
     *      proof's public signals and compare it against stored tender state.
     *      A contract must never accept limbs it did not itself derive from
     *      storage.
     */
    function fromLimbs(uint256 hi, uint256 lo) internal pure returns (bytes32) {
        if (hi >= (1 << 128) || lo >= (1 << 128)) revert LimbExceeds128Bits();
        return bytes32((hi << 128) | lo);
    }

    /// @notice Split a 32-byte hash into two 128-bit limbs. Spec Section 4.
    function toLimbs(bytes32 hash) internal pure returns (uint256 hi, uint256 lo) {
        hi = uint256(hash) >> 128;
        lo = uint256(hash) & ((1 << 128) - 1);
    }

    /**
     * @notice tenderIdField = toField(keccak256(DOMAIN || utf8(tenderId))).
     *         Spec Section 5.
     * @dev Checked on-chain at activation so the derivation cannot be spoofed.
     */
    function tenderIdField(string memory tenderId) internal pure returns (uint256) {
        return toField(keccak256(abi.encodePacked(RAW_TENDER_ID_V1, tenderId)));
    }

    /// @notice Poseidon over two field elements. Merkle parent. Spec Section 12.
    function hash2(uint256 left, uint256 right) internal pure returns (uint256) {
        return PoseidonT3.hash([left, right]);
    }

    /**
     * @notice The bid leaf. Spec Section 12, whitepaper Section 7.
     *
     * @dev FOUR inputs plus the domain constant. `storageReceiptRoot` is
     *      deliberately not part of the leaf: it is verified at acceptance and
     *      stored in the bid record. Including it would make every on-chain
     *      root disagree with the award statement the whitepaper publishes.
     */
    function bidLeaf(
        uint256 nullifier,
        uint256 bidCommitment,
        uint256 ciphertextHashField,
        uint256 submissionIndex
    ) internal pure returns (uint256) {
        return
            PoseidonT6.hash(
                [
                    DOMAIN_LEAF_V1,
                    nullifier,
                    bidCommitment,
                    ciphertextHashField,
                    submissionIndex
                ]
            );
    }
}
