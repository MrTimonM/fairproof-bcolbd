pragma circom 2.2.2;

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "constants.circom";

/*
 * The composite Poseidon digests of docs/field-encoding.md Sections 8-12.
 *
 * Every template here has an exact counterpart in
 * packages/crypto/src/poseidon.ts. The cross-language equality test asserts
 * they agree byte for byte.
 */

// subjectCommitment = Poseidon2(DOMAIN_SUBJECT_V1, subjectSecret). Spec 9.
template SubjectCommitment() {
    signal input subjectSecret;
    signal output out;

    component h = Poseidon(2);
    h.inputs[0] <== DOMAIN_SUBJECT_V1();
    h.inputs[1] <== subjectSecret;
    out <== h.out;
}

// nullifier = Poseidon3(DOMAIN_NULLIFIER_V1, subjectSecret, tenderIdField).
// Spec Section 9, whitepaper Section 5 clause 8.
template Nullifier() {
    signal input subjectSecret;
    signal input tenderIdField;
    signal output out;

    component h = Poseidon(3);
    h.inputs[0] <== DOMAIN_NULLIFIER_V1();
    h.inputs[1] <== subjectSecret;
    h.inputs[2] <== tenderIdField;
    out <== h.out;
}

// bidCommitment = Poseidon5(DOMAIN, bidAmount, bidNonce, tenderIdField, nullifier).
// Spec Section 10, whitepaper Section 5 clause 9.
//
// bidNonce is what makes this hiding; without it Poseidon(7400000) is
// grindable in seconds (whitepaper Table 4, dictionary attack).
template BidCommitment() {
    signal input bidAmount;
    signal input bidNonce;
    signal input tenderIdField;
    signal input nullifier;
    signal output out;

    component h = Poseidon(5);
    h.inputs[0] <== DOMAIN_BIDCOMMIT_V1();
    h.inputs[1] <== bidAmount;
    h.inputs[2] <== bidNonce;
    h.inputs[3] <== tenderIdField;
    h.inputs[4] <== nullifier;
    out <== h.out;
}

/*
 * credDigest: the single field element the issuer signs with EdDSA-Poseidon.
 * Spec Section 8.
 *
 * THE FIELD ORDER IS CANONICAL. Any reordering relative to
 * packages/crypto/src/poseidon.ts credDigest() produces a signature failure
 * that presents as a curve bug and costs days to find.
 */
template CredDigest() {
    signal input schemaVersion;
    signal input subjectCommitment;
    signal input annualTurnover;
    signal input relevantExperience;
    signal input certificationCode;
    signal input certValidUntil;
    signal input credentialValidUntil;
    signal input credentialId;
    signal input issuerEpoch;
    signal input issuedAt;
    signal output out;

    component h1 = Poseidon(6);
    h1.inputs[0] <== DOMAIN_CRED_V1();
    h1.inputs[1] <== schemaVersion;
    h1.inputs[2] <== subjectCommitment;
    h1.inputs[3] <== annualTurnover;
    h1.inputs[4] <== relevantExperience;
    h1.inputs[5] <== certificationCode;

    component h2 = Poseidon(5);
    h2.inputs[0] <== certValidUntil;
    h2.inputs[1] <== credentialValidUntil;
    h2.inputs[2] <== credentialId;
    h2.inputs[3] <== issuerEpoch;
    h2.inputs[4] <== issuedAt;

    component h3 = Poseidon(2);
    h3.inputs[0] <== h1.out;
    h3.inputs[1] <== h2.out;
    out <== h3.out;
}

/*
 * Bid leaf. Spec Section 12, whitepaper Section 7.
 *
 * FOUR inputs plus the domain constant. storageReceiptRoot is deliberately
 * NOT in the leaf - it is checked at acceptance and stored in the bid record.
 */
template BidLeaf() {
    signal input nullifier;
    signal input bidCommitment;
    signal input ciphertextHashField;
    signal input submissionIndex;
    signal output out;

    component h = Poseidon(5);
    h.inputs[0] <== DOMAIN_LEAF_V1();
    h.inputs[1] <== nullifier;
    h.inputs[2] <== bidCommitment;
    h.inputs[3] <== ciphertextHashField;
    h.inputs[4] <== submissionIndex;
    out <== h.out;
}
