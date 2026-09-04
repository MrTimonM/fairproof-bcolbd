// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {BabyJubjub} from "../lib/BabyJubjub.sol";

/**
 * @notice TEST ONLY. Exposes BabyJubjub's internals so the cross-language
 *         equality test can compare Solidity against circomlibjs directly,
 *         rather than only through the tender contract's aggregate result.
 *
 *         A curve-arithmetic bug that only shows up as "setCommitteeKey
 *         reverted" is nearly impossible to localise; these entry points make
 *         the failing operation visible.
 */
contract BabyJubjubHarness {
    function inCurve(uint256 x, uint256 y) external pure returns (bool) {
        return BabyJubjub.inCurve(x, y);
    }

    function isInPrimeSubgroup(uint256 x, uint256 y) external pure returns (bool) {
        return BabyJubjub.isInPrimeSubgroup(x, y);
    }

    function add(uint256 x1, uint256 y1, uint256 x2, uint256 y2)
        external
        view
        returns (uint256 x, uint256 y)
    {
        BabyJubjub.Proj memory r = BabyJubjub.add(
            BabyJubjub.toProj(x1, y1),
            BabyJubjub.toProj(x2, y2)
        );
        return _affine(r);
    }

    function mul(uint256 x, uint256 y, uint256 scalar)
        external
        view
        returns (uint256, uint256)
    {
        return _affine(BabyJubjub.mul(BabyJubjub.toProj(x, y), scalar));
    }

    function mulBase(uint256 scalar) external view returns (uint256, uint256) {
        return
            _affine(
                BabyJubjub.mul(
                    BabyJubjub.toProj(BabyJubjub.BASE8X, BabyJubjub.BASE8Y),
                    scalar
                )
            );
    }

    function expectedPublicShare(
        uint256[] calldata commitmentX,
        uint256[] calldata commitmentY,
        uint256 index
    ) external view returns (uint256, uint256) {
        return _affine(BabyJubjub.expectedPublicShare(commitmentX, commitmentY, index));
    }

    function subOrder() external pure returns (uint256) {
        return BabyJubjub.SUB_ORDER;
    }

    function prime() external pure returns (uint256) {
        return BabyJubjub.P;
    }

    /**
     * @dev Projective to affine, for comparison against circomlibjs's affine
     *      output. The single inversion here is why the library itself avoids
     *      affine conversion: production code compares projectively.
     */
    function _affine(BabyJubjub.Proj memory p)
        private
        view
        returns (uint256, uint256)
    {
        uint256 inv = _invert(p.z);
        return (
            mulmod(p.x, inv, BabyJubjub.P),
            mulmod(p.y, inv, BabyJubjub.P)
        );
    }

    /// @dev z^(P-2) mod P via the modexp precompile.
    function _invert(uint256 z) private view returns (uint256 result) {
        uint256 p = BabyJubjub.P;
        bool ok;
        assembly {
            let m := mload(0x40)
            mstore(m, 0x20)
            mstore(add(m, 0x20), 0x20)
            mstore(add(m, 0x40), 0x20)
            mstore(add(m, 0x60), z)
            mstore(add(m, 0x80), sub(p, 2))
            mstore(add(m, 0xa0), p)
            ok := staticcall(gas(), 0x05, m, 0xc0, m, 0x20)
            result := mload(m)
        }
        require(ok, "modexp failed");
    }
}
