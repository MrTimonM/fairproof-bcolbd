// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IFairProofErrors} from "./interfaces/IFairProofErrors.sol";
import {BabyJubjub} from "./lib/BabyJubjub.sol";
import {Governance} from "./Governance.sol";
import {SealedBid} from "./SealedBid.sol";
import {TenderRegistry} from "./TenderRegistry.sol";

/**
 * @title OpeningManager
 * @notice The 3-of-5 threshold opening ceremony, with every decryption share
 *         verified on-chain.
 *
 * @dev Development plan Section 12.6, whitepaper Section 6.
 *
 *      WHY THE PROOFS ARE VERIFIED HERE AND NOT IN THE APPLICATION.
 *
 *      A decryption share `D_i = x_i * R` is just a curve point. Nothing about
 *      it says which member produced it. Without a proof, a member could
 *      publish any point at all; the Lagrange combination would produce
 *      garbage, and the failure would surface later as an AES-GCM tag error
 *      that looks like the BIDDER's fault. The plan is explicit that "an
 *      invalid share is rejected and attributed, not silently dropped", and
 *      attribution is only possible if the share carries a proof.
 *
 *      So each share arrives with a Chaum-Pedersen proof that
 *      `log_G(Y_i) = log_R(D_i)` - that the same secret relates the member's
 *      published public share to the share they are now submitting - and this
 *      contract checks it. A share that fails REVERTS, naming the member
 *      index. The reverted transaction is itself the public record: it is
 *      mined, its sender is recorded, and its revert reason names who
 *      submitted what.
 *
 *      THE CONTRACT NEVER RECONSTRUCTS THE SECRET. It counts and verifies
 *      shares; the Lagrange interpolation happens in the application, in the
 *      exponent, producing `S = x * R` without the tender secret existing
 *      anywhere. A contract that reconstructed `x` would be a contract that
 *      published it.
 *
 *      TWO SHARES ARE NOT ENOUGH, AND THAT IS OBSERVABLE. `openingStatus`
 *      returns the count and the threshold separately so the UI can show
 *      1/3, then 2/3, with decryption still impossible - the step that
 *      distinguishes a real threshold from a two-party check.
 *
 * @dev WHAT THIS DOES NOT PREVENT, stated plainly. These events evidence the
 *      OFFICIAL ceremony. Three colluding members could exchange shares
 *      privately and open bids early, and nothing on-chain would reveal it.
 *      Whitepaper Sections 4 and 19.5 concede exactly this; the UI must repeat
 *      it wherever the threshold is displayed rather than letting a reviewer
 *      discover it.
 */
contract OpeningManager is IFairProofErrors {
    /// @notice Whitepaper Section 6: three of five.
    uint8 public constant THRESHOLD = 3;
    uint8 public constant COMMITTEE_SIZE = 5;

    /// @dev keccak256("FairProof:ciphertext:v1"). Spec Section 3.
    bytes32 internal constant RAW_CIPHERTEXT_V1 =
        0x6edc5e8537624c6e297a0e49274ec5a5e66270f9402ff011206b0c1793896729;
    /// @dev keccak256("FairProof:dleq:v1"). Spec Section 21.
    bytes32 internal constant RAW_DLEQ_V1 =
        0x90fcb89fb43b96167b00efaf2bbe93dea466b042c0be602817027df1ed2a572c;

    /**
     * @dev Byte offsets of the ElGamal ephemeral point inside the canonical
     *      ciphertext. Spec Section 11 fixes the layout:
     *      version(1) || R.x(32) || R.y(32) || wrapped(32) || iv(12) ||
     *      ctLen(4) || ct(ctLen) || tag(16)
     */
    uint256 internal constant OFFSET_RX = 1;
    uint256 internal constant OFFSET_RY = 33;
    /// @dev version + R + wrapped + iv + ctLen + tag, with an empty ct.
    uint256 internal constant MIN_CIPHERTEXT_BYTES = 1 + 32 + 32 + 32 + 12 + 4 + 16;
    uint8 internal constant CIPHERTEXT_VERSION = 1;

    /// @notice A Chaum-Pedersen proof. Spec Section 21.
    struct DleqProof {
        /// @dev A = w * G
        uint256 aX;
        uint256 aY;
        /// @dev B = w * R
        uint256 bX;
        uint256 bY;
        /// @dev z = w + e * x_i (mod SUB_ORDER)
        uint256 z;
    }

    /// @notice One member's verified decryption share.
    struct Share {
        uint8 memberIndex; // 1-based, matching Feldman
        uint256 dX;
        uint256 dY;
        address submitter;
        uint64 acceptedAt;
    }

    struct Ciphertext {
        bool revealed;
        uint256 rX;
        uint256 rY;
        uint32 byteLength;
        uint64 revealedAt;
    }

    Governance public immutable governance;
    TenderRegistry public immutable tenderRegistry;
    SealedBid public immutable sealedBid;

    /// @dev tenderId => bidIndex => the published ciphertext's ephemeral point.
    mapping(bytes32 => mapping(uint8 => Ciphertext)) private _ciphertexts;
    /// @dev tenderId => bidIndex => accepted shares, in submission order.
    mapping(bytes32 => mapping(uint8 => Share[])) private _shares;
    /// @dev tenderId => bidIndex => memberIndex => already submitted.
    mapping(bytes32 => mapping(uint8 => mapping(uint8 => bool))) public shareSubmitted;

    error TenderNotClosed(bytes32 tenderId, uint8 state);
    error NoSuchBid(bytes32 tenderId, uint8 bidIndex);
    error CiphertextNotRevealed(bytes32 tenderId, uint8 bidIndex);
    error CiphertextAlreadyRevealed(bytes32 tenderId, uint8 bidIndex);
    error CiphertextHashMismatch(bytes32 expected, bytes32 actual);
    error CiphertextTooShort(uint256 length, uint256 minimum);
    error CiphertextVersionUnsupported(uint8 version);
    error CiphertextLengthInconsistent(uint256 declared, uint256 actual);
    error EphemeralNotOnCurve(uint256 rX, uint256 rY);
    error EphemeralNotInSubgroup(uint256 rX, uint256 rY);
    error NotThisCommitteeMember(uint8 memberIndex, address caller, address expected);
    error MemberIndexOutOfRange(uint8 memberIndex);
    error ShareAlreadySubmitted(uint8 memberIndex);
    error ShareNotOnCurve(uint8 memberIndex);
    error DleqProofMalformed(uint8 memberIndex);
    error DleqProofInvalid(uint8 memberIndex, address submitter);
    error ThresholdAlreadyReached(bytes32 tenderId, uint8 bidIndex);

    event CiphertextRevealed(
        bytes32 indexed tenderId,
        uint8 indexed bidIndex,
        bytes32 ciphertextHash,
        uint256 rX,
        uint256 rY,
        uint32 byteLength
    );
    event DecryptionShareAccepted(
        bytes32 indexed tenderId,
        uint8 indexed bidIndex,
        uint8 indexed memberIndex,
        uint256 dX,
        uint256 dY,
        uint8 accepted,
        uint8 threshold,
        address submitter
    );
    event OpeningThresholdReached(
        bytes32 indexed tenderId,
        uint8 indexed bidIndex,
        uint8 threshold,
        uint64 at
    );

    constructor(
        Governance governance_,
        TenderRegistry tenderRegistry_,
        SealedBid sealedBid_
    ) {
        governance = governance_;
        tenderRegistry = tenderRegistry_;
        sealedBid = sealedBid_;
    }

    /**
     * @dev The tender must be CLOSED.
     *
     *      Plan Section 12.6 step 2: "OpeningManager refuses every share
     *      submitted before the deadline." CLOSED is the state that only
     *      exists after the deadline, so requiring it is the check - and
     *      because `closeTender` is permissionless, nobody can hold a tender
     *      open to delay an opening either.
     */
    modifier onlyClosed(bytes32 tenderId) {
        TenderRegistry.State state = tenderRegistry.getState(tenderId);
        if (state != TenderRegistry.State.CLOSED) {
            revert TenderNotClosed(tenderId, uint8(state));
        }
        _;
    }

    // ----------------------------------------------------- revealing the body

    /**
     * @notice Publish a bid's ciphertext body, verified against its commitment.
     *
     * @dev The chain stores only `ciphertextHash` at submission time, so it
     *      does not know the ElGamal ephemeral point `R` - and without `R`
     *      there is nothing to verify a DLEQ proof against. The body is
     *      therefore published once per bid at opening time and hashed HERE,
     *      so the bytes everyone opens are provably the bytes that were
     *      committed to before the deadline.
     *
     *      Permissionless: publishing an already-committed ciphertext reveals
     *      nothing (it is still encrypted), and requiring a privileged caller
     *      would let that caller stall every opening.
     *
     *      This also makes the evidence bundle self-contained - the ciphertext
     *      is on-chain rather than only in a replica that might be gone by the
     *      time anyone audits.
     */
    function revealCiphertext(
        bytes32 tenderId,
        uint8 bidIndex,
        bytes calldata canonicalBytes
    ) external onlyClosed(tenderId) {
        if (bidIndex >= sealedBid.submissionCount(tenderId)) {
            revert NoSuchBid(tenderId, bidIndex);
        }
        Ciphertext storage c = _ciphertexts[tenderId][bidIndex];
        if (c.revealed) revert CiphertextAlreadyRevealed(tenderId, bidIndex);

        if (canonicalBytes.length < MIN_CIPHERTEXT_BYTES) {
            revert CiphertextTooShort(canonicalBytes.length, MIN_CIPHERTEXT_BYTES);
        }
        if (uint8(canonicalBytes[0]) != CIPHERTEXT_VERSION) {
            revert CiphertextVersionUnsupported(uint8(canonicalBytes[0]));
        }

        bytes32 expected = sealedBid.getBid(tenderId, bidIndex).ciphertextHash;
        bytes32 actual = keccak256(abi.encodePacked(RAW_CIPHERTEXT_V1, canonicalBytes));
        if (actual != expected) revert CiphertextHashMismatch(expected, actual);

        // The declared ct length must account for exactly the remaining bytes.
        // The hash already pins the whole string, so this cannot change what
        // is opened - but a body whose internal length disagrees with its size
        // would be parsed differently by different readers, and the point of a
        // canonical encoding is that it cannot be.
        uint256 declared = uint32(bytes4(canonicalBytes[109:113]));
        if (declared + MIN_CIPHERTEXT_BYTES != canonicalBytes.length) {
            revert CiphertextLengthInconsistent(declared, canonicalBytes.length);
        }

        uint256 rX = uint256(bytes32(canonicalBytes[OFFSET_RX:OFFSET_RX + 32]));
        uint256 rY = uint256(bytes32(canonicalBytes[OFFSET_RY:OFFSET_RY + 32]));
        if (!BabyJubjub.inCurve(rX, rY)) revert EphemeralNotOnCurve(rX, rY);
        // A non-subgroup R would make the DLEQ statement meaningless: a member
        // could satisfy it for a point carrying a small-order component and
        // the combination would not yield the true shared secret.
        if (!BabyJubjub.isInPrimeSubgroup(rX, rY)) revert EphemeralNotInSubgroup(rX, rY);

        c.revealed = true;
        c.rX = rX;
        c.rY = rY;
        c.byteLength = uint32(canonicalBytes.length);
        c.revealedAt = uint64(block.timestamp);

        emit CiphertextRevealed(
            tenderId,
            bidIndex,
            expected,
            rX,
            rY,
            uint32(canonicalBytes.length)
        );
    }

    // ------------------------------------------------------------ the shares

    /**
     * @notice Submit a decryption share with its Chaum-Pedersen proof.
     *
     * @param memberIndex 1-based, matching Feldman. Index 0 would be the
     *        polynomial at zero - the tender secret itself - so it is never a
     *        member.
     */
    function submitDecryptionShare(
        bytes32 tenderId,
        uint8 bidIndex,
        uint8 memberIndex,
        uint256 dX,
        uint256 dY,
        DleqProof calldata proof
    ) external onlyClosed(tenderId) returns (uint8 accepted) {
        if (memberIndex == 0 || memberIndex > COMMITTEE_SIZE) {
            revert MemberIndexOutOfRange(memberIndex);
        }
        Ciphertext storage c = _ciphertexts[tenderId][bidIndex];
        if (!c.revealed) revert CiphertextNotRevealed(tenderId, bidIndex);
        if (shareSubmitted[tenderId][bidIndex][memberIndex]) {
            revert ShareAlreadySubmitted(memberIndex);
        }

        // The caller must BE the member whose share this is. Otherwise a
        // member could publish another member's share and the attribution in
        // the events would be wrong - which matters precisely because these
        // events are the evidence that the ceremony was held.
        address expected = tenderRegistry.getCommitteeMembers(tenderId)[memberIndex - 1];
        if (msg.sender != expected) {
            revert NotThisCommitteeMember(memberIndex, msg.sender, expected);
        }

        if (!BabyJubjub.inCurve(dX, dY)) revert ShareNotOnCurve(memberIndex);
        if (
            !BabyJubjub.inCurve(proof.aX, proof.aY) ||
            !BabyJubjub.inCurve(proof.bX, proof.bY) ||
            proof.z == 0 ||
            proof.z >= BabyJubjub.SUB_ORDER
        ) {
            revert DleqProofMalformed(memberIndex);
        }

        TenderRegistry.CommitteeKey memory key = tenderRegistry.getCommitteeKey(tenderId);
        if (
            !_verifyDleq(
                key.memberX[memberIndex - 1],
                key.memberY[memberIndex - 1],
                c.rX,
                c.rY,
                dX,
                dY,
                proof
            )
        ) {
            // Reverting IS the attribution. The transaction is mined with
            // status 0, its sender is recorded, and the reason names the
            // member index - so a rejected share is a permanent public fact
            // rather than something the application chose not to display.
            revert DleqProofInvalid(memberIndex, msg.sender);
        }

        shareSubmitted[tenderId][bidIndex][memberIndex] = true;
        _shares[tenderId][bidIndex].push(
            Share({
                memberIndex: memberIndex,
                dX: dX,
                dY: dY,
                submitter: msg.sender,
                acceptedAt: uint64(block.timestamp)
            })
        );
        accepted = uint8(_shares[tenderId][bidIndex].length);

        emit DecryptionShareAccepted(
            tenderId,
            bidIndex,
            memberIndex,
            dX,
            dY,
            accepted,
            THRESHOLD,
            msg.sender
        );
        if (accepted == THRESHOLD) {
            emit OpeningThresholdReached(tenderId, bidIndex, THRESHOLD, uint64(block.timestamp));
        }
    }

    /**
     * @dev Chaum-Pedersen verification. Spec Section 21.
     *
     *          z*G == A + e*Y_i     and     z*R == B + e*D_i
     *
     *      with `e` the Fiat-Shamir challenge over BOTH statements and BOTH
     *      commitments. Omitting `R` or `D_i` from the challenge would let a
     *      member prove once and have that proof accepted for every bid in the
     *      tender.
     *
     *      Both equations are required. Checking only the first would prove
     *      the member knows `x_i` and say nothing about the point they
     *      actually submitted.
     */
    function _verifyDleq(
        uint256 yX,
        uint256 yY,
        uint256 rX,
        uint256 rY,
        uint256 dX,
        uint256 dY,
        DleqProof calldata proof
    ) private pure returns (bool) {
        uint256 e = uint256(
            keccak256(
                abi.encodePacked(
                    RAW_DLEQ_V1,
                    BabyJubjub.BASE8X,
                    BabyJubjub.BASE8Y,
                    yX,
                    yY,
                    rX,
                    rY,
                    dX,
                    dY,
                    proof.aX,
                    proof.aY,
                    proof.bX,
                    proof.bY
                )
            )
        ) % BabyJubjub.SUB_ORDER;

        BabyJubjub.Proj memory lhs1 = BabyJubjub.mul(
            BabyJubjub.toProj(BabyJubjub.BASE8X, BabyJubjub.BASE8Y),
            proof.z
        );
        BabyJubjub.Proj memory rhs1 = BabyJubjub.add(
            BabyJubjub.toProj(proof.aX, proof.aY),
            BabyJubjub.mul(BabyJubjub.toProj(yX, yY), e)
        );
        if (!_projEqual(lhs1, rhs1)) return false;

        BabyJubjub.Proj memory lhs2 = BabyJubjub.mul(BabyJubjub.toProj(rX, rY), proof.z);
        BabyJubjub.Proj memory rhs2 = BabyJubjub.add(
            BabyJubjub.toProj(proof.bX, proof.bY),
            BabyJubjub.mul(BabyJubjub.toProj(dX, dY), e)
        );
        return _projEqual(lhs2, rhs2);
    }

    /**
     * @dev Projective equality by cross-multiplication: (X1:Y1:Z1) equals
     *      (X2:Y2:Z2) iff X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1. No inversion,
     *      and no conversion to affine that could differ by a representation.
     */
    function _projEqual(BabyJubjub.Proj memory a, BabyJubjub.Proj memory b)
        private
        pure
        returns (bool)
    {
        uint256 p = BabyJubjub.P;
        return
            mulmod(a.x, b.z, p) == mulmod(b.x, a.z, p) &&
            mulmod(a.y, b.z, p) == mulmod(b.y, a.z, p);
    }

    // ---------------------------------------------------------------- reading

    /**
     * @notice Progress for one bid.
     * @dev `accepted` and `threshold` are returned separately so the UI can
     *      render 1/3 and 2/3 with decryption still impossible. Collapsing
     *      them into a single boolean would hide the step that distinguishes a
     *      real threshold from a two-party check (plan Section 12.7).
     */
    function openingStatus(bytes32 tenderId, uint8 bidIndex)
        external
        view
        returns (bool revealed, uint8 accepted, uint8 threshold, bool ready)
    {
        Ciphertext storage c = _ciphertexts[tenderId][bidIndex];
        accepted = uint8(_shares[tenderId][bidIndex].length);
        return (c.revealed, accepted, THRESHOLD, accepted >= THRESHOLD);
    }

    function getCiphertext(bytes32 tenderId, uint8 bidIndex)
        external
        view
        returns (Ciphertext memory)
    {
        return _ciphertexts[tenderId][bidIndex];
    }

    /// @notice The accepted shares, for the application's exponent-side
    ///         Lagrange interpolation. Publishing them is safe: they are
    ///         per-tender, per-ciphertext values, not long-lived secrets, and
    ///         publishing them is what makes the ceremony verifiable by anyone.
    function getShares(bytes32 tenderId, uint8 bidIndex)
        external
        view
        returns (Share[] memory)
    {
        return _shares[tenderId][bidIndex];
    }

    function shareCount(bytes32 tenderId, uint8 bidIndex) external view returns (uint8) {
        return uint8(_shares[tenderId][bidIndex].length);
    }
}
