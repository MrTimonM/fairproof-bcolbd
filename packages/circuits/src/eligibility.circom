pragma circom 2.2.2;

include "../../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "constants.circom";
include "commitments.circom";
include "merkle.circom";

/*
 * The FairProof eligibility circuit.
 *
 * Implements the NINE clauses of whitepaper Figure 3 exactly - no additions to
 * the public signal list, no clause omitted. The clause numbers in the
 * comments below are the whitepaper's own.
 *
 * What the chain learns: that an approved, unrevoked issuer attested facts
 * meeting the committed thresholds, and nothing else. It does NOT learn the
 * turnover, the experience, or the bid amount.
 *
 * SAFETY RULE THAT GOVERNS THIS WHOLE FILE (docs/field-encoding.md Section 14):
 * every comparison is preceded by an explicit Num2Bits range constraint on
 * BOTH operands. An unconstrained LessThan in Circom is not a comparison; it
 * is a suggestion, and a malicious prover supplies a field element that wraps.
 * This is the most likely place a real soundness bug would hide, so the
 * negative test suite attacks it directly.
 */
template Eligibility(issuerTreeDepth, revocationTreeDepth) {

    // ---------------------------------------------------------------
    // PRIVATE WITNESS - never leaves the bidder's device.
    // Not encrypted, not uploaded, not escrowed.
    // ---------------------------------------------------------------
    signal input subjectSecret;

    // Credential attributes, signed by the issuer.
    signal input annualTurnover;         // T,   uint64, BDT taka
    signal input relevantExperience;     // E_m, uint32, months
    signal input certificationCode;      // uint64
    signal input certValidUntil;         // uint64, UTC seconds
    signal input credentialValidUntil;   // uint64, UTC seconds
    signal input credentialId;           // uint64
    signal input issuedAt;               // uint64, UTC seconds

    // Issuer signature and key.
    signal input issuerPubKeyX;
    signal input issuerPubKeyY;
    signal input issuerSigR8x;
    signal input issuerSigR8y;
    signal input issuerSigS;

    // Merkle witnesses.
    signal input issuerPathElements[issuerTreeDepth];
    signal input issuerPathIndices[issuerTreeDepth];
    signal input revocationPathElements[revocationTreeDepth];

    // Bid binding.
    signal input bidAmount;              // uint64, BDT minor unit
    signal input bidNonce;               // 248-bit CSPRNG

    // ---------------------------------------------------------------
    // PUBLIC SIGNALS - whitepaper Figure 3, in the order of
    // docs/field-encoding.md Section 16.
    // ---------------------------------------------------------------
    signal input tenderIdField;
    signal input rulesHashHi;
    signal input rulesHashLo;
    signal input turnoverThreshold;
    signal input experienceMonthsThreshold;
    signal input requiredCertificationCode;
    signal input deadline;
    signal input issuerRegistryRoot;
    signal input revocationRoot;
    signal input credentialEpoch;
    signal input nullifier;
    signal input bidCommitment;

    // ===============================================================
    // Range constraints FIRST. Every value that will be compared, or
    // that must not wrap, is bit-constrained before any use.
    // ===============================================================
    component rngTurnover = Num2Bits(64);   rngTurnover.in <== annualTurnover;
    component rngThreshT  = Num2Bits(64);   rngThreshT.in  <== turnoverThreshold;
    component rngExp      = Num2Bits(32);   rngExp.in      <== relevantExperience;
    component rngThreshE  = Num2Bits(32);   rngThreshE.in  <== experienceMonthsThreshold;
    component rngCertVal  = Num2Bits(64);   rngCertVal.in  <== certValidUntil;
    component rngCredVal  = Num2Bits(64);   rngCredVal.in  <== credentialValidUntil;
    component rngDeadline = Num2Bits(64);   rngDeadline.in <== deadline;
    component rngIssuedAt = Num2Bits(64);   rngIssuedAt.in <== issuedAt;
    component rngCredId   = Num2Bits(64);   rngCredId.in   <== credentialId;
    component rngBidAmt   = Num2Bits(64);   rngBidAmt.in   <== bidAmount;
    component rngCertCode = Num2Bits(64);   rngCertCode.in <== certificationCode;
    component rngReqCode  = Num2Bits(64);   rngReqCode.in  <== requiredCertificationCode;
    component rngEpoch    = Num2Bits(32);   rngEpoch.in    <== credentialEpoch;

    // ===============================================================
    // CLAUSE 4: the signed subjectCommitment equals Poseidon(subjectSecret).
    //
    // Computed first because the signature is over a digest that includes it.
    // This is what prevents one credential from generating many nullifiers:
    // the subject binding is inside the issuer's signature.
    // ===============================================================
    component subj = SubjectCommitment();
    subj.subjectSecret <== subjectSecret;

    // ===============================================================
    // The credential digest the issuer signed (spec Section 8).
    // ===============================================================
    component digest = CredDigest();
    digest.schemaVersion <== SCHEMA_VERSION();
    digest.subjectCommitment <== subj.out;
    digest.annualTurnover <== annualTurnover;
    digest.relevantExperience <== relevantExperience;
    digest.certificationCode <== certificationCode;
    digest.certValidUntil <== certValidUntil;
    digest.credentialValidUntil <== credentialValidUntil;
    digest.credentialId <== credentialId;
    digest.issuerEpoch <== credentialEpoch;
    digest.issuedAt <== issuedAt;

    // ===============================================================
    // CLAUSE 1: the issuer signature verifies over the credential fields.
    //
    // This is the root of input authenticity. Without it the circuit would
    // prove only that "someone typed a number above the threshold"
    // (whitepaper Section 4).
    // ===============================================================
    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== issuerPubKeyX;
    sig.Ay <== issuerPubKeyY;
    sig.R8x <== issuerSigR8x;
    sig.R8y <== issuerSigR8y;
    sig.S <== issuerSigS;
    sig.M <== digest.out;

    // ===============================================================
    // CLAUSE 2: issuerPubKey is a MEMBER of issuerRegistryRoot.
    //
    // A valid signature alone is not enough: anyone can sign. Membership is
    // what makes the key an APPROVED issuer's key, and it is why the registry
    // publishes a Merkle root rather than only a storage mapping - a circuit
    // cannot read contract storage.
    //
    // The leaf commits to both coordinates, so a prover cannot swap in a
    // different point that shares one coordinate.
    // ===============================================================
    component issuerLeaf = Poseidon(2);
    issuerLeaf.inputs[0] <== issuerPubKeyX;
    issuerLeaf.inputs[1] <== issuerPubKeyY;

    component issuerPath = MerkleProof(issuerTreeDepth);
    issuerPath.leaf <== issuerLeaf.out;
    for (var i = 0; i < issuerTreeDepth; i++) {
        issuerPath.siblings[i] <== issuerPathElements[i];
        issuerPath.pathIndices[i] <== issuerPathIndices[i];
    }
    issuerPath.root === issuerRegistryRoot;

    // ===============================================================
    // CLAUSE 3: the sparse-Merkle leaf at credentialId equals zero.
    //
    // A zero leaf PROVES non-revocation. Zero is the correct empty value here
    // - unlike the bid tree - because this is a sparse tree keyed by
    // credentialId, where an all-zero subtree is the expected default rather
    // than an ambiguity (whitepaper Section 5).
    //
    // The path indices are the bits of credentialId, so the prover cannot
    // choose which leaf to open.
    // ===============================================================
    component revocation = SparseNonMembership(revocationTreeDepth);
    revocation.credentialId <== credentialId;
    for (var i = 0; i < revocationTreeDepth; i++) {
        revocation.siblings[i] <== revocationPathElements[i];
    }
    revocation.root <== revocationRoot;

    // ===============================================================
    // CLAUSE 5: T >= turnoverThreshold.
    //
    // Both operands are range-constrained above. LessThan(65) is deliberate:
    // with 64-bit operands the comparison needs one extra bit of headroom.
    // ===============================================================
    component turnoverOk = LessThan(65);
    turnoverOk.in[0] <== turnoverThreshold;
    turnoverOk.in[1] <== annualTurnover + 1;   // threshold < T+1  <=>  T >= threshold
    turnoverOk.out === 1;

    // ===============================================================
    // CLAUSE 6: E_m >= experienceMonthsThreshold.
    // ===============================================================
    component experienceOk = LessThan(33);
    experienceOk.in[0] <== experienceMonthsThreshold;
    experienceOk.in[1] <== relevantExperience + 1;
    experienceOk.out === 1;

    // Required certification matches. Whitepaper Figure 3 folds this into the
    // certification clause; stated separately here because an equality check
    // and a validity check are different failures and the UI must name them
    // differently (plan Section 18.4).
    certificationCode === requiredCertificationCode;

    // ===============================================================
    // CLAUSE 7: certValidUntil >= deadline.
    //
    // The certificate must still be valid ON THE DEADLINE DATE, not merely on
    // the day the proof is generated.
    // ===============================================================
    component certOk = LessThan(65);
    certOk.in[0] <== deadline;
    certOk.in[1] <== certValidUntil + 1;
    certOk.out === 1;

    // Credential expiry. A SUPERSET of the whitepaper's nine clauses, kept
    // because an expired credential should not qualify even if the
    // certificate it references has not expired. Documented as a superset;
    // never presented as one of the nine.
    component credOk = LessThan(65);
    credOk.in[0] <== deadline;
    credOk.in[1] <== credentialValidUntil + 1;
    credOk.out === 1;

    // ===============================================================
    // CLAUSE 8: nullifier == Poseidon(subjectSecret, tenderIdField).
    //
    // Tender-bound, so one firm gets one nullifier per tender and cannot bid
    // twice under different pseudonyms; and the nullifier differs across
    // tenders, so participation cannot be linked.
    // ===============================================================
    component nul = Nullifier();
    nul.subjectSecret <== subjectSecret;
    nul.tenderIdField <== tenderIdField;
    nul.out === nullifier;

    // ===============================================================
    // CLAUSE 9: bidCommitment == Poseidon(bidAmount, bidNonce, tenderIdField,
    //                                     nullifier).
    //
    // Joint binding prevents proof transfer and bid substitution: the proof
    // is useless with any other bid, and the bid is useless with any other
    // proof.
    // ===============================================================
    component bc = BidCommitment();
    bc.bidAmount <== bidAmount;
    bc.bidNonce <== bidNonce;
    bc.tenderIdField <== tenderIdField;
    bc.nullifier <== nul.out;
    bc.out === bidCommitment;

    // ===============================================================
    // rulesHashHi / rulesHashLo carry NO in-circuit constraint, and need
    // none. Any change to them changes the verified statement, so a proof
    // built under different rules simply fails at the verifier, which
    // compares the reconstructed hash against the tender's stored rulesHash.
    // Adding a decorative constraint here would suggest the binding lives in
    // the circuit when it actually lives in the verifier adapter.
    //
    // They are consumed so the compiler does not prune them from the public
    // input vector.
    // ===============================================================
    signal rulesHashBinding;
    rulesHashBinding <== rulesHashHi * 0 + rulesHashLo * 0;
    rulesHashBinding === 0;
}

component main {
    public [
        tenderIdField,
        rulesHashHi,
        rulesHashLo,
        turnoverThreshold,
        experienceMonthsThreshold,
        requiredCertificationCode,
        deadline,
        issuerRegistryRoot,
        revocationRoot,
        credentialEpoch,
        nullifier,
        bidCommitment
    ]
} = Eligibility(4, 32);
