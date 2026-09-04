// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/**
 * @title IWinnerIdentityVerifier
 * @notice The snarkjs-generated winner-identity verifier.
 *
 * @dev FIVE public signals. docs/field-encoding.md Section 18 originally
 *      listed four; `issuerRegistryRoot` was added during implementation
 *      because without it the circuit's registry-membership check is vacuous.
 *      The amendment is recorded in that section.
 *
 *      Returns false rather than reverting, like every other generated
 *      verifier here. The return value must be checked.
 */
interface IWinnerIdentityVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[5] calldata pubSignals
    ) external view returns (bool);
}
