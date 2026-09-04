// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/**
 * @title IAwardVerifier
 * @notice The snarkjs-generated award verifier, as AwardManager sees it.
 *
 * @dev EIGHT public signals, fixed by whitepaper Section 7 and
 *      docs/field-encoding.md Section 17. The width is part of the type, so a
 *      verifier built for a different circuit cannot be called through this
 *      interface at all - the ABI decode fails rather than silently reading
 *      adjacent calldata.
 *
 *      Like the eligibility verifier, this RETURNS FALSE rather than
 *      reverting, including for a public signal that is not a valid field
 *      element. Ignoring the return value would accept every proof.
 */
interface IAwardVerifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[8] calldata pubSignals
    ) external view returns (bool);
}
