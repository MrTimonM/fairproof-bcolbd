const assert = require("node:assert/strict");
const hre = require("hardhat");

/**
 * IncrementalMerkleTree: the on-chain accumulator the completeness claim
 * rests on.
 *
 * Whitepaper Section 7: "bidSetRoot is accumulated by the contract, not
 * supplied by the authority, so a proof computed over a smaller set ... will
 * not verify against the root the chain already holds."
 *
 * The expected roots below come from packages/crypto (TypeScript). If Solidity
 * and TypeScript disagree by one hash, every award proof fails against the
 * chain's root - so these are equality assertions, not sanity checks.
 */

const DOMAIN_PADDING_V1 =
  118794039896364772078121437224410514784736280784934280083252483328023231778n;

// Frozen values from docs/field-encoding.md / packages/crypto.
const EMPTY_ROOT_D5 =
  18232377929263394053032240335347245131877279331383963775401837732819763548351n;
const BID_LEAF =
  15340760414361073061137857190954650095246937439854762262721043353673380374339n;
const ONE_LEAF_ROOT_D5 =
  14465473130413919901910704099017925969547638565783553852358863928953031517182n;

const NULLIFIER =
  10300773402810884556227667586735294835071807663997647123131005278771083756748n;
const BID_COMMITMENT =
  9232367608476292032797277960384312713271221383973505300636200737204852886374n;
const CIPHERTEXT_HASH_FIELD = 99887766554433221100998877665544332211009988776655n;

describe("IncrementalMerkleTree", function () {
  this.timeout(180000);

  let libs;

  before(async () => {
    const t3 = await hre.viem.deployContract("PoseidonT3");
    const t6 = await hre.viem.deployContract("PoseidonT6");
    libs = {
      "poseidon-solidity/PoseidonT3.sol:PoseidonT3": t3.address,
      "poseidon-solidity/PoseidonT6.sol:PoseidonT6": t6.address,
    };
  });

  const tree = (depth) =>
    hre.viem.deployContract("MerkleHarness", [depth], { libraries: libs });

  describe("empty tree", () => {
    it("matches the TypeScript empty root at depth 5", async () => {
      const t = await tree(5);
      assert.equal(await t.read.root(), EMPTY_ROOT_D5);
    });

    it("has capacity MAX_BIDS = 32 at depth 5", async () => {
      const t = await tree(5);
      assert.equal(await t.read.capacity(), 32);
      assert.equal(await t.read.leafCount(), 0);
    });

    it("the empty root is not zero", async () => {
      // A zero root would be indistinguishable from an uninitialised tree.
      const t = await tree(5);
      assert.notEqual(await t.read.root(), 0n);
    });

    it("rejects depth 0 and depth above 32", async () => {
      await assert.rejects(() => tree(0), /DepthOutOfRange/);
      await assert.rejects(() => tree(33), /DepthOutOfRange/);
    });
  });

  describe("appending leaves", () => {
    it("one leaf produces the TypeScript one-leaf root", async () => {
      const t = await tree(5);
      await t.write.insert([BID_LEAF]);
      assert.equal(await t.read.leafCount(), 1);
      assert.equal(
        await t.read.root(),
        ONE_LEAF_ROOT_D5,
        "Solidity and TypeScript accumulators must agree exactly",
      );
    });

    it("computes the bid leaf itself, matching the frozen value", async () => {
      const t = await tree(5);
      await t.write.insertBidLeaf([
        NULLIFIER,
        BID_COMMITMENT,
        CIPHERTEXT_HASH_FIELD,
        0n,
      ]);
      assert.equal((await t.read.leaves())[0], BID_LEAF);
      assert.equal(await t.read.root(), ONE_LEAF_ROOT_D5);
    });

    it("the root changes on every append", async () => {
      const t = await tree(5);
      const seen = new Set([String(await t.read.root())]);
      for (let i = 1n; i <= 8n; i++) {
        await t.write.insert([BID_LEAF + i]);
        const r = String(await t.read.root());
        assert.equal(seen.has(r), false, `root repeated after append ${i}`);
        seen.add(r);
      }
    });

    it("returns sequential indices", async () => {
      const t = await tree(5);
      for (let i = 0; i < 4; i++) {
        await t.write.insert([BID_LEAF + BigInt(i)]);
        assert.equal(await t.read.leafCount(), i + 1);
      }
    });

    it("preserves the ordered leaf list, so the award witness is rebuildable", async () => {
      const t = await tree(5);
      const inserted = [11n, 22n, 33n];
      for (const l of inserted) await t.write.insert([l]);
      assert.deepEqual(await t.read.leaves(), inserted);
    });

    it("rejects the 33rd leaf at MAX_BIDS = 32", async () => {
      // Whitepaper Section 7: capacity exhaustion rejects further bids
      // BEFORE acceptance, so this must revert rather than silently drop.
      const t = await tree(5);
      for (let i = 0; i < 32; i++) await t.write.insert([BID_LEAF + BigInt(i)]);
      assert.equal(await t.read.leafCount(), 32);
      await assert.rejects(
        () => t.write.insert([999n]),
        /CapacityExhausted/,
      );
    });
  });

  /**
   * These are the completeness properties. If any fails, the "dropped
   * accepted bid" attack of whitepaper Table 4 succeeds.
   */
  describe("completeness (whitepaper Table 4, dropped accepted bid)", () => {
    async function rootOf(leaves, depth = 5) {
      const t = await tree(depth);
      for (const l of leaves) await t.write.insert([l]);
      return t.read.root();
    }

    it("omitting a leaf changes the root", async () => {
      const full = await rootOf([1n, 2n, 3n, 4n]);
      const dropped = await rootOf([1n, 2n, 4n]);
      assert.notEqual(dropped, full);
    });

    it("adding an unaccepted leaf changes the root", async () => {
      const full = await rootOf([1n, 2n, 3n, 4n]);
      const extra = await rootOf([1n, 2n, 3n, 4n, 5n]);
      assert.notEqual(extra, full);
    });

    it("altering a leaf changes the root", async () => {
      const full = await rootOf([1n, 2n, 3n, 4n]);
      const altered = await rootOf([1n, 99n, 3n, 4n]);
      assert.notEqual(altered, full);
    });

    it("reordering leaves changes the root", async () => {
      // Order is part of the rule: whitepaper Section 3.1 ties the tie-break
      // to finalized submission sequence.
      const full = await rootOf([1n, 2n, 3n, 4n]);
      const swapped = await rootOf([2n, 1n, 3n, 4n]);
      assert.notEqual(swapped, full);
    });

    it("substituting the padding leaf for a real leaf is detectable", async () => {
      const full = await rootOf([1n, 2n, 3n, 4n]);
      const padded = await rootOf([1n, 2n, DOMAIN_PADDING_V1, 4n]);
      assert.notEqual(
        padded,
        full,
        "a real leaf must not be swappable for an apparently-empty slot",
      );
    });

    it("the padding leaf is not zero", async () => {
      assert.notEqual(DOMAIN_PADDING_V1, 0n);
    });
  });

  describe("measured gas (plan Section 22)", () => {
    it("reports append cost at depth 5", async () => {
      const t = await tree(5);
      // First append: all-empty siblings.
      const firstGas = await t.read.measureInsertGas([BID_LEAF]);
      await t.write.insert([BID_LEAF]);
      // Second append: pairs with a cached sibling at level 0.
      const secondGas = await t.read.measureInsertGas([BID_LEAF + 1n]);
      console.log(`      append #1 (execution): ${firstGas} gas`);
      console.log(`      append #2 (execution): ${secondGas} gas`);
      // Recorded, not asserted against a target. Whitepaper Table 15 commits
      // to measured values rather than design targets.
      assert.ok(firstGas > 0n);
    });
  });
});
