/**
 * Incremental fixed-depth binary Merkle tree, matching the Solidity
 * accumulator in SealedBid. Spec Section 12.
 *
 * This is the accumulator the completeness claim rests on: the contract, not
 * the authority, computes bidSetRoot, so an award proof over a smaller set
 * cannot verify against the root the chain already holds (whitepaper S7).
 */
import { BID_TREE_DEPTH, DOMAIN_PADDING_V1 } from "./domains.js";
import { merkleParent, zeroHashes } from "./poseidon.js";

export interface MerkleProof {
  leaf: bigint;
  index: number;
  /** Sibling at each level, from leaf upward */
  siblings: bigint[];
  /** 0 = node is the left child, 1 = right child, from leaf upward */
  pathIndices: number[];
  root: bigint;
}

export class IncrementalMerkleTree {
  readonly depth: number;
  readonly capacity: number;
  private readonly zeros: bigint[];
  private leaves: bigint[] = [];

  constructor(depth: number = BID_TREE_DEPTH) {
    this.depth = depth;
    this.capacity = 2 ** depth;
    this.zeros = zeroHashes(depth);
  }

  get size(): number {
    return this.leaves.length;
  }

  /** Append a leaf. Throws at capacity, mirroring the contract's rejection. */
  insert(leaf: bigint): number {
    if (this.leaves.length >= this.capacity) {
      throw new Error(
        `IncrementalMerkleTree: capacity ${this.capacity} exhausted`,
      );
    }
    this.leaves.push(leaf);
    return this.leaves.length - 1;
  }

  /** Padded leaf vector of length `capacity`, as the award circuit sees it. */
  paddedLeaves(): bigint[] {
    const padded = [...this.leaves];
    while (padded.length < this.capacity) padded.push(DOMAIN_PADDING_V1);
    return padded;
  }

  /** Current root. An empty tree has root zeros[depth]. */
  root(): bigint {
    let level = this.paddedLeaves();
    for (let d = 0; d < this.depth; d++) {
      const next: bigint[] = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(merkleParent(level[i], level[i + 1]));
      }
      level = next;
    }
    return level[0];
  }

  /** Inclusion proof for the leaf at `index`. */
  proof(index: number): MerkleProof {
    if (index < 0 || index >= this.capacity) {
      throw new Error(`IncrementalMerkleTree: index ${index} out of range`);
    }
    const siblings: bigint[] = [];
    const pathIndices: number[] = [];

    let level = this.paddedLeaves();
    let idx = index;
    for (let d = 0; d < this.depth; d++) {
      const isRight = idx % 2 === 1;
      siblings.push(level[isRight ? idx - 1 : idx + 1]);
      pathIndices.push(isRight ? 1 : 0);

      const next: bigint[] = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(merkleParent(level[i], level[i + 1]));
      }
      level = next;
      idx = Math.floor(idx / 2);
    }

    return {
      leaf: this.paddedLeaves()[index],
      index,
      siblings,
      pathIndices,
      root: level[0],
    };
  }

  /** Verify a proof independently of the tree that produced it. */
  static verify(proof: MerkleProof): boolean {
    let node = proof.leaf;
    for (let d = 0; d < proof.siblings.length; d++) {
      node =
        proof.pathIndices[d] === 1
          ? merkleParent(proof.siblings[d], node)
          : merkleParent(node, proof.siblings[d]);
    }
    return node === proof.root;
  }

  /** Root of an empty tree at the given depth. */
  static emptyRoot(depth: number = BID_TREE_DEPTH): bigint {
    return zeroHashes(depth)[depth];
  }
}

/**
 * Build a root from an explicit ordered leaf list, padding to `2**depth`.
 * Used for the issuer registry and the storage-receipt trees.
 */
export function rootFromLeaves(leaves: bigint[], depth: number): bigint {
  const capacity = 2 ** depth;
  if (leaves.length > capacity) {
    throw new Error(`rootFromLeaves: ${leaves.length} leaves exceeds depth ${depth}`);
  }
  const tree = new IncrementalMerkleTree(depth);
  for (const leaf of leaves) tree.insert(leaf);
  return tree.root();
}
