import { beforeAll, describe, expect, it } from "vitest";
import {
  BID_TREE_DEPTH,
  DOMAIN_PADDING_V1,
  IncrementalMerkleTree,
  MAX_BIDS,
  bidLeaf,
  initPoseidon,
  rootFromLeaves,
} from "../src/index.js";

beforeAll(async () => {
  await initPoseidon();
});

function leaf(i: number): bigint {
  return bidLeaf({
    nullifier: BigInt(1000 + i),
    bidCommitment: BigInt(2000 + i),
    ciphertextHashField: BigInt(3000 + i),
    submissionIndex: i,
  });
}

describe("incremental merkle tree (spec Section 12)", () => {
  it("an empty tree has the pinned empty root", () => {
    const tree = new IncrementalMerkleTree(BID_TREE_DEPTH);
    expect(tree.root()).toBe(IncrementalMerkleTree.emptyRoot(BID_TREE_DEPTH));
  });

  it("capacity is MAX_BIDS", () => {
    expect(new IncrementalMerkleTree(BID_TREE_DEPTH).capacity).toBe(MAX_BIDS);
  });

  it("the root changes on every insert", () => {
    const tree = new IncrementalMerkleTree();
    const seen = new Set<string>([tree.root().toString()]);
    for (let i = 0; i < 8; i++) {
      tree.insert(leaf(i));
      const r = tree.root().toString();
      expect(seen.has(r), `root repeated after insert ${i}`).toBe(false);
      seen.add(r);
    }
  });

  it("rejects the 33rd bid, matching the contract's capacity check", () => {
    const tree = new IncrementalMerkleTree();
    for (let i = 0; i < MAX_BIDS; i++) tree.insert(leaf(i));
    expect(tree.size).toBe(MAX_BIDS);
    expect(() => tree.insert(leaf(99))).toThrow(/capacity 32 exhausted/);
  });

  it("pads unused slots with the padding domain, not zero", () => {
    const tree = new IncrementalMerkleTree();
    tree.insert(leaf(0));
    const padded = tree.paddedLeaves();
    expect(padded).toHaveLength(MAX_BIDS);
    expect(padded[1]).toBe(DOMAIN_PADDING_V1);
    expect(padded[1]).not.toBe(0n);
  });

  it("produces verifiable inclusion proofs for every leaf", () => {
    const tree = new IncrementalMerkleTree();
    for (let i = 0; i < 5; i++) tree.insert(leaf(i));
    for (let i = 0; i < 5; i++) {
      const proof = tree.proof(i);
      expect(proof.siblings).toHaveLength(BID_TREE_DEPTH);
      expect(IncrementalMerkleTree.verify(proof), `leaf ${i}`).toBe(true);
    }
  });

  it("a tampered proof does not verify", () => {
    const tree = new IncrementalMerkleTree();
    for (let i = 0; i < 4; i++) tree.insert(leaf(i));
    const proof = tree.proof(2);
    expect(
      IncrementalMerkleTree.verify({ ...proof, leaf: proof.leaf + 1n }),
    ).toBe(false);
    const siblings = [...proof.siblings];
    siblings[0] = siblings[0] + 1n;
    expect(IncrementalMerkleTree.verify({ ...proof, siblings })).toBe(false);
  });
});

/**
 * These are the completeness properties whitepaper Section 7 relies on.
 * If any of them fails, the "dropped accepted bid" attack succeeds.
 */
describe("bid-set completeness (whitepaper Section 7)", () => {
  // Built lazily: Poseidon is not initialised at module-evaluation time.
  let leaves: bigint[];
  beforeAll(() => {
    leaves = [0, 1, 2, 3].map((i) => leaf(i));
  });

  it("omitting an accepted leaf changes the root", () => {
    const full = rootFromLeaves(leaves, BID_TREE_DEPTH);
    const dropped = rootFromLeaves(
      [leaves[0], leaves[1], leaves[3]],
      BID_TREE_DEPTH,
    );
    expect(dropped).not.toBe(full);
  });

  it("inserting an unaccepted leaf changes the root", () => {
    const full = rootFromLeaves(leaves, BID_TREE_DEPTH);
    const extra = rootFromLeaves([...leaves, leaf(99)], BID_TREE_DEPTH);
    expect(extra).not.toBe(full);
  });

  it("altering a leaf changes the root", () => {
    const full = rootFromLeaves(leaves, BID_TREE_DEPTH);
    const altered = rootFromLeaves(
      [leaves[0], leaves[1] + 1n, leaves[2], leaves[3]],
      BID_TREE_DEPTH,
    );
    expect(altered).not.toBe(full);
  });

  it("reordering leaves changes the root, since order is part of the rule", () => {
    const full = rootFromLeaves(leaves, BID_TREE_DEPTH);
    const swapped = rootFromLeaves(
      [leaves[1], leaves[0], leaves[2], leaves[3]],
      BID_TREE_DEPTH,
    );
    expect(swapped).not.toBe(full);
  });

  it("a padding leaf cannot be substituted for a real leaf undetected", () => {
    const full = rootFromLeaves(leaves, BID_TREE_DEPTH);
    const padded = rootFromLeaves(
      [leaves[0], leaves[1], DOMAIN_PADDING_V1, leaves[3]],
      BID_TREE_DEPTH,
    );
    expect(padded).not.toBe(full);
  });

  it("rejects more leaves than the depth allows", () => {
    expect(() => rootFromLeaves(new Array(5).fill(1n), 2)).toThrow(
      /exceeds depth 2/,
    );
  });
});
