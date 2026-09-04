pragma circom 2.2.2;

include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "constants.circom";
include "commitments.circom";
include "merkle.circom";

/**
 * The winner-identity ownership proof.
 *
 * Development plan Section 9.7, whitepaper Section 7. Public signals per
 * docs/field-encoding.md Section 18.
 *
 * WHY THIS EXISTS. After the award, the winning bid is a commitment and a
 * nullifier - no name attached. Displaying a legal identity next to it on the
 * authority's word alone would put the whole confidentiality design at the
 * mercy of a database edit. So the winner proves, before any identity is
 * shown, that it is the party that placed the winning bid.
 *
 * WHAT IS PROVED
 *
 *   1. The prover knows `subjectSecret` such that
 *      `nullifier == Poseidon(DOMAIN_NULLIFIER_V1, subjectSecret, tenderIdField)`.
 *   2. The same secret opens the `subjectCommitment` inside a credential
 *      signed by an issuer in the published registry. So the winner is not
 *      merely someone who knows a secret - they are the holder of a real
 *      qualification credential.
 *   3. The same nullifier, with the bid amount and nonce, reproduces
 *      `winnerCommitment` - tying the identity to the specific winning bid
 *      rather than to participation in general.
 *   4. `legalIdentityCommitment` is bound to that credential's `credentialId`
 *      and to the hash of the record the winner published.
 *
 * The issuer-registry root is a FIFTH public signal. Section 18 originally
 * listed four; the root was added during implementation because without it
 * the membership check is vacuous - the prover supplies both the path and the
 * root. See the note on the signal itself.
 *
 * WHAT IS NOT PROVED, and it matters: that the declared legal name is
 * accurate. Nothing cryptographic stops a party misdescribing itself. What
 * bounds it is that the record carries `credentialId`, so the issuer who
 * signed that credential can confirm the declaration. The report's row must
 * read "linked to the credential holder", not "legal identity verified".
 *
 * NO THRESHOLDS AND NO REVOCATION CHECK HERE. This circuit answers "who won",
 * not "were they eligible" - eligibility was proved at submission and again at
 * the deadline. Re-checking thresholds would add constraints and prove nothing
 * new, and asking for a revocation path would make the identity step fail for
 * a credential revoked after the award, which is not what the step is for.
 */
template WinnerIdentity(issuerTreeDepth) {
    // ---- private ---------------------------------------------------------
    signal input subjectSecret;

    // Credential attributes, exactly the fields credDigest covers.
    signal input annualTurnover;
    signal input relevantExperience;
    signal input certificationCode;
    signal input certValidUntil;
    signal input credentialValidUntil;
    signal input credentialId;
    signal input issuerEpoch;
    signal input issuedAt;

    // Issuer signature and key.
    signal input issuerPubKeyX;
    signal input issuerPubKeyY;
    signal input issuerSigR8x;
    signal input issuerSigR8y;
    signal input issuerSigS;

    signal input issuerPathElements[issuerTreeDepth];
    signal input issuerPathIndices[issuerTreeDepth];

    // The winning bid's opened values.
    signal input bidAmount;
    signal input bidNonce;

    /// @dev toField(keccak256(RAW_IDENTITY_RECORD_V1 || JCS(record))).
    ///      Private here; the CONTRACT recomputes it from the published record
    ///      and rebuilds the commitment, so it cannot be swapped.
    signal input legalIdentityHash;

    // ---- public ----------------------------------------------------------
    signal input tenderIdField;
    signal input winnerCommitment;
    signal input nullifier;
    signal input legalIdentityCommitment;
    /**
     * The published issuer-registry root for the tender's epoch.
     *
     * A FIFTH public signal, added to Section 18 during implementation, and
     * the reason is a soundness gap rather than a convenience.
     *
     * With four signals the membership check below was vacuous: the prover
     * supplies both the path and the root, so any key at all can be made to
     * "verify", and a winner could mint their own issuer, sign a credential
     * carrying somebody else's `credentialId`, and publish an identity record
     * naming it. They would still genuinely own the winning bid - but the
     * check that lets the ISSUER confirm the declaration, which is the only
     * thing bounding the honesty of a self-declared legal name, would be
     * worthless.
     *
     * Exposing the root lets the contract compare it against
     * `IssuerRegistry.issuerRegistryRoot(epoch)`, exactly as the eligibility
     * adapter does, which makes the membership claim mean something.
     */
    signal input issuerRegistryRoot;

    // =====================================================================
    // Ranges first. Same rule as every other circuit here
    // (docs/field-encoding.md Section 14): a comparison or a hash input that
    // has not been range-constrained is an invitation to supply a field
    // element that wraps. Nothing below compares, but credDigest must receive
    // the same widths the issuer signed over or a different digest results.
    // =====================================================================
    component turnoverBits = Num2Bits(64);
    turnoverBits.in <== annualTurnover;
    component experienceBits = Num2Bits(32);
    experienceBits.in <== relevantExperience;
    component certCodeBits = Num2Bits(64);
    certCodeBits.in <== certificationCode;
    component certValidBits = Num2Bits(64);
    certValidBits.in <== certValidUntil;
    component credValidBits = Num2Bits(64);
    credValidBits.in <== credentialValidUntil;
    component credIdBits = Num2Bits(64);
    credIdBits.in <== credentialId;
    component epochBits = Num2Bits(64);
    epochBits.in <== issuerEpoch;
    component issuedAtBits = Num2Bits(64);
    issuedAtBits.in <== issuedAt;
    component amountBits = Num2Bits(64);
    amountBits.in <== bidAmount;

    // =====================================================================
    // 1. The nullifier comes from this subjectSecret and this tender.
    // =====================================================================
    component nul = Nullifier();
    nul.subjectSecret <== subjectSecret;
    nul.tenderIdField <== tenderIdField;
    nul.out === nullifier;

    // =====================================================================
    // 2. The same secret opens the credential's subjectCommitment, and the
    //    credential is signed by an issuer in the published registry.
    // =====================================================================
    component subject = SubjectCommitment();
    subject.subjectSecret <== subjectSecret;

    component digest = CredDigest();
    digest.schemaVersion <== SCHEMA_VERSION();
    digest.subjectCommitment <== subject.out;
    digest.annualTurnover <== annualTurnover;
    digest.relevantExperience <== relevantExperience;
    digest.certificationCode <== certificationCode;
    digest.certValidUntil <== certValidUntil;
    digest.credentialValidUntil <== credentialValidUntil;
    digest.credentialId <== credentialId;
    digest.issuerEpoch <== issuerEpoch;
    digest.issuedAt <== issuedAt;

    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== issuerPubKeyX;
    sig.Ay <== issuerPubKeyY;
    sig.R8x <== issuerSigR8x;
    sig.R8y <== issuerSigR8y;
    sig.S <== issuerSigS;
    sig.M <== digest.out;

    // The issuer key must be in the registry. The leaf commits to BOTH
    // coordinates, so a prover cannot substitute a different curve point
    // sharing one coordinate.
    component issuerLeaf = Poseidon(2);
    issuerLeaf.inputs[0] <== issuerPubKeyX;
    issuerLeaf.inputs[1] <== issuerPubKeyY;

    component issuerPath = MerkleProof(issuerTreeDepth);
    issuerPath.leaf <== issuerLeaf.out;
    for (var i = 0; i < issuerTreeDepth; i++) {
        issuerPath.siblings[i] <== issuerPathElements[i];
        issuerPath.pathIndices[i] <== issuerPathIndices[i];
    }
    // The reconstructed root must be the published one. See the note on
    // `issuerRegistryRoot` above for why this is a public signal.
    issuerPath.root === issuerRegistryRoot;

    // =====================================================================
    // 3. The identity is tied to the WINNING BID, not to participation.
    // =====================================================================
    component commitment = BidCommitment();
    commitment.bidAmount <== bidAmount;
    commitment.bidNonce <== bidNonce;
    commitment.tenderIdField <== tenderIdField;
    commitment.nullifier <== nullifier;
    commitment.out === winnerCommitment;

    // =====================================================================
    // 4. The commitment binds the credential id and the published record.
    //
    //    Two nested arity-2 hashes rather than one arity-3, so no third
    //    Poseidon library has to be deployed on-chain. Spec Section 23 fixes
    //    the nesting order.
    // =====================================================================
    component idInner = Poseidon(2);
    idInner.inputs[0] <== DOMAIN_IDENTITY_V1();
    idInner.inputs[1] <== credentialId;

    component idOuter = Poseidon(2);
    idOuter.inputs[0] <== idInner.out;
    idOuter.inputs[1] <== legalIdentityHash;

    idOuter.out === legalIdentityCommitment;
}

component main {
    public [
        tenderIdField,
        winnerCommitment,
        nullifier,
        legalIdentityCommitment,
        issuerRegistryRoot
    ]
} = WinnerIdentity(ISSUER_TREE_DEPTH());
