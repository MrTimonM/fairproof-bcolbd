pragma circom 2.2.2;

/*
 * Frozen protocol constants. docs/field-encoding.md Section 3.
 *
 * These MUST equal the values in packages/crypto/src/domains.ts and the
 * literals pinned in packages/crypto/test/domains.test.ts. Agreement is
 * enforced by the cross-language equality test (dev plan Section 11A.6).
 *
 * Circom has no shared-constant mechanism across files, so these are
 * functions rather than variables.
 */

// toField(keccak256("FairProof:cred:v1"))
function DOMAIN_CRED_V1() {
    return 322149158785522698676451765976810572237009812112012877722857913027064676009;
}

// toField(keccak256("FairProof:leaf:v1"))
function DOMAIN_LEAF_V1() {
    return 190845489973463437363397010865843301780418146225117113041917773882994065432;
}

// toField(keccak256("FairProof:padding:v1"))
// The empty/padding leaf. NOT zero: a zero leaf is indistinguishable from an
// empty subtree and invites a completeness bypass.
function DOMAIN_PADDING_V1() {
    return 118794039896364772078121437224410514784736280784934280083252483328023231778;
}

// toField(keccak256("FairProof:nullifier:v1"))
function DOMAIN_NULLIFIER_V1() {
    return 332042671396993988458214105119834532491316109751507750077714947830527129332;
}

// toField(keccak256("FairProof:bidCommitment:v1"))
function DOMAIN_BIDCOMMIT_V1() {
    return 139370848049544989023910287186176558846770354377755241435164208878574711998;
}

// toField(keccak256("FairProof:subject:v1"))
/** toField(keccak256("FairProof:identity:v1")). Spec Section 23. */
function DOMAIN_IDENTITY_V1() {
    return 350255550607654703349396198304734656087699665840881769065044796263778895484;
}

function DOMAIN_SUBJECT_V1() {
    return 63384362855929274650512957064135432067752122244173505609908999325216133498;
}

// Credential schema version for this release.
function SCHEMA_VERSION() {
    return 1;
}

// Whitepaper Section 7: the award circuit supports MAX_BIDS = 32.
function MAX_BIDS() {
    return 32;
}

function BID_TREE_DEPTH() {
    return 5;
}

function ISSUER_TREE_DEPTH() {
    return 4;
}

function REVOCATION_TREE_DEPTH() {
    return 32;
}
