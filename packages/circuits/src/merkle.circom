pragma circom 2.2.2;

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "constants.circom";

/*
 * Merkle machinery. docs/field-encoding.md Sections 12, 13, 15.
 */

// One level of a binary Merkle path. pathIndex selects child ordering:
// 0 = the running node is the left child, 1 = the right child.
template MerkleLevel() {
    signal input node;
    signal input sibling;
    signal input pathIndex;
    signal output out;

    // pathIndex must be boolean, or a prover could select a third ordering.
    pathIndex * (pathIndex - 1) === 0;

    component muxLeft = Mux1();
    muxLeft.c[0] <== node;
    muxLeft.c[1] <== sibling;
    muxLeft.s <== pathIndex;

    component muxRight = Mux1();
    muxRight.c[0] <== sibling;
    muxRight.c[1] <== node;
    muxRight.s <== pathIndex;

    component h = Poseidon(2);
    h.inputs[0] <== muxLeft.out;
    h.inputs[1] <== muxRight.out;
    out <== h.out;
}

// Recompute a Merkle root from a leaf and its path.
template MerkleProof(depth) {
    signal input leaf;
    signal input siblings[depth];
    signal input pathIndices[depth];
    signal output root;

    component levels[depth];
    for (var i = 0; i < depth; i++) {
        levels[i] = MerkleLevel();
        levels[i].node <== (i == 0) ? leaf : levels[i - 1].out;
        levels[i].sibling <== siblings[i];
        levels[i].pathIndex <== pathIndices[i];
    }

    root <== levels[depth - 1].out;
}

/*
 * Sparse Merkle non-membership, for the revocation tree. Spec Section 15.
 *
 * Whitepaper Section 5 clause 3: "Sparse-Merkle leaf at credentialId equals
 * zero". Zero IS the correct empty value here - unlike the bid tree - because
 * it is a sparse tree keyed by credentialId where an all-zero subtree is the
 * expected default state rather than an ambiguity.
 *
 * The path indices are the bits of credentialId, so the leaf position is
 * bound to the identifier rather than freely chosen by the prover.
 */
template SparseNonMembership(depth) {
    signal input credentialId;
    signal input siblings[depth];
    signal input root;

    // Decompose credentialId into path bits. Num2Bits range-constrains it,
    // so a prover cannot supply a wrapping field element.
    component bits = Num2Bits(depth);
    bits.in <== credentialId;

    // The claimed leaf is zero: the credential is not revoked.
    component path = MerkleProof(depth);
    path.leaf <== 0;
    for (var i = 0; i < depth; i++) {
        path.siblings[i] <== siblings[i];
        path.pathIndices[i] <== bits.out[i];
    }

    path.root === root;
}

/*
 * Full fixed-size tree root from all 2**depth leaves.
 *
 * The award circuit needs this rather than per-leaf membership: membership
 * proves each leaf is present, never that no leaf was OMITTED, which is
 * exactly the "dropped accepted bid" attack (whitepaper Table 4).
 */
template FullMerkleRoot(depth) {
    var nLeaves = 1 << depth;
    signal input leaves[nLeaves];
    signal output root;

    // Flattened tree: level 0 is the leaves, then each level halves.
    component hashers[nLeaves - 1];
    signal nodes[2 * nLeaves - 1];

    for (var i = 0; i < nLeaves; i++) {
        nodes[i] <== leaves[i];
    }

    var offset = 0;
    var width = nLeaves;
    var next = nLeaves;
    var h = 0;
    while (width > 1) {
        for (var i = 0; i < width; i += 2) {
            hashers[h] = Poseidon(2);
            hashers[h].inputs[0] <== nodes[offset + i];
            hashers[h].inputs[1] <== nodes[offset + i + 1];
            nodes[next] <== hashers[h].out;
            next++;
            h++;
        }
        offset += width;
        width = width \ 2;
    }

    root <== nodes[2 * nLeaves - 2];
}
