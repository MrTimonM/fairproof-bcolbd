// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/**
 * @title IGroth16Verifier
 * @notice The snarkjs-generated eligibility verifier, as the adapter sees it.
 *
 * @dev The generated verifier RETURNS FALSE; it does not revert. It returns
 *      false for a bad pairing and also for a public signal that is not a
 *      valid field element. Ignoring the return value would therefore accept
 *      every proof, and no test that only submits valid proofs would notice.
 *      Every call site in this repository must branch on the result.
 *
 *      The signal array width is part of the type. A verifier built for a
 *      different circuit has a different width, so a mismatched verifier
 *      cannot be called through this interface at all - the ABI decode fails
 *      rather than silently reading adjacent calldata.
 */
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[12] calldata pubSignals
    ) external view returns (bool);
}
