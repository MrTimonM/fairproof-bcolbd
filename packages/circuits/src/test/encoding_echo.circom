pragma circom 2.2.2;

include "../commitments.circom";
include "../merkle.circom";

/*
 * Test-only circuit for the cross-language equality test
 * (development plan Section 11A.6).
 *
 * It computes every composite digest of the frozen spec and exposes them as
 * public outputs, so a test can assert byte-for-byte agreement with
 * packages/crypto (TypeScript) and with the deployed Poseidon (Solidity).
 *
 * This circuit is NEVER deployed. It exists only to detect the single most
 * expensive class of bug in this project: a field-order or constant mismatch
 * between the three implementations, which presents as an inexplicable
 * signature or Merkle failure days later.
 */
template EncodingEcho() {
    // --- inputs, mirroring the committed test vector ---
    signal input subjectSecret;
    signal input tenderIdField;
    signal input bidAmount;
    signal input bidNonce;
    signal input ciphertextHashField;
    signal input submissionIndex;

    signal input annualTurnover;
    signal input relevantExperience;
    signal input certificationCode;
    signal input certValidUntil;
    signal input credentialValidUntil;
    signal input credentialId;
    signal input issuerEpoch;
    signal input issuedAt;

    // --- outputs ---
    signal output outPoseidon2;
    signal output outSubjectCommitment;
    signal output outNullifier;
    signal output outBidCommitment;
    signal output outCredDigest;
    signal output outBidLeaf;
    signal output outEmptyRoot;

    // Bare Poseidon(1, 2), the circomlib reference vector.
    component p2 = Poseidon(2);
    p2.inputs[0] <== 1;
    p2.inputs[1] <== 2;
    outPoseidon2 <== p2.out;

    component subj = SubjectCommitment();
    subj.subjectSecret <== subjectSecret;
    outSubjectCommitment <== subj.out;

    component nul = Nullifier();
    nul.subjectSecret <== subjectSecret;
    nul.tenderIdField <== tenderIdField;
    outNullifier <== nul.out;

    component bc = BidCommitment();
    bc.bidAmount <== bidAmount;
    bc.bidNonce <== bidNonce;
    bc.tenderIdField <== tenderIdField;
    bc.nullifier <== nul.out;
    outBidCommitment <== bc.out;

    component cd = CredDigest();
    cd.schemaVersion <== SCHEMA_VERSION();
    cd.subjectCommitment <== subj.out;
    cd.annualTurnover <== annualTurnover;
    cd.relevantExperience <== relevantExperience;
    cd.certificationCode <== certificationCode;
    cd.certValidUntil <== certValidUntil;
    cd.credentialValidUntil <== credentialValidUntil;
    cd.credentialId <== credentialId;
    cd.issuerEpoch <== issuerEpoch;
    cd.issuedAt <== issuedAt;
    outCredDigest <== cd.out;

    component leaf = BidLeaf();
    leaf.nullifier <== nul.out;
    leaf.bidCommitment <== bc.out;
    leaf.ciphertextHashField <== ciphertextHashField;
    leaf.submissionIndex <== submissionIndex;
    outBidLeaf <== leaf.out;

    // Empty bid-set root: all 32 slots are the padding leaf.
    component emptyTree = FullMerkleRoot(BID_TREE_DEPTH());
    for (var i = 0; i < 32; i++) {
        emptyTree.leaves[i] <== DOMAIN_PADDING_V1();
    }
    outEmptyRoot <== emptyTree.root;
}

component main = EncodingEcho();
