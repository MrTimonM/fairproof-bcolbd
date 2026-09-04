const assert = require("node:assert/strict");
const hre = require("hardhat");

/**
 * The Solidity leg of the cross-language equality test.
 * Development plan Section 11A.6.
 *
 * The expected values below are the FROZEN protocol digests, computed over the
 * committed test vector in packages/circuits/test/vector.ts. The same literals
 * are asserted in packages/crypto/test/domains.test.ts, and the Circom leg
 * asserts equality against the TypeScript implementation. All three
 * implementations therefore pin the same values independently.
 *
 * If a test here fails, DO NOT update the literal. The frozen encoding in
 * docs/field-encoding.md changed, and that is a breaking protocol change.
 */

// Committed test vector (packages/circuits/test/vector.ts)
const VECTOR = {
  tenderId: "FP-00014",
  bidAmount: 7400000n,
  ciphertextHashField:
    99887766554433221100998877665544332211009988776655n,
  submissionIndex: 0n,
};

// Frozen expected digests
const EXPECTED = {
  tenderIdField:
    345466083462855046233379317649602515757229700962688122897585307103576758497n,
  nullifier:
    10300773402810884556227667586735294835071807663997647123131005278771083756748n,
  bidCommitment:
    9232367608476292032797277960384312713271221383973505300636200737204852886374n,
  bidLeaf:
    15340760414361073061137857190954650095246937439854762262721043353673380374339n,
  emptyRoot:
    18232377929263394053032240335347245131877279331383963775401837732819763548351n,
  oneLeafRoot:
    14465473130413919901910704099017925969547638565783553852358863928953031517182n,
  poseidon2_1_2:
    7853200120776062878684798364095072458815029376092732009249414926327459813530n,
};

const DOMAIN_PADDING_V1 =
  118794039896364772078121437224410514784736280784934280083252483328023231778n;

describe("Solidity <-> frozen encoding agreement", function () {
  this.timeout(120000);
  let harness;

  before(async () => {
    // Poseidon is deployed once and linked. Both libraries fit under
    // EIP-170 with optimizer runs=1, so no raised size limit is needed.
    const t3 = await hre.viem.deployContract("PoseidonT3");
    const t6 = await hre.viem.deployContract("PoseidonT6");
    harness = await hre.viem.deployContract("EncodingHarness", [], {
      libraries: {
        "poseidon-solidity/PoseidonT3.sol:PoseidonT3": t3.address,
        "poseidon-solidity/PoseidonT6.sol:PoseidonT6": t6.address,
      },
    });
  });

  describe("field truncation (spec Section 2)", () => {
    it("keeps the high 248 bits, never reducing mod p", async () => {
      const allOnes = "0x" + "ff".repeat(32);
      assert.equal(
        await harness.read.toField([allOnes]),
        (1n << 248n) - 1n,
        "toField must be a right shift, not a modular reduction",
      );
    });

    it("discards exactly the low byte", async () => {
      const d = "0x" + "00".repeat(30) + "1234";
      assert.equal(await harness.read.toField([d]), 0x12n);
    });
  });

  describe("rulesHash limbs (spec Section 4)", () => {
    const hash =
      "0x8f3a2b1c4d5e6f708192a3b4c5d6e7f80112233445566778899aabbccddeeff0";

    it("round-trips losslessly, so the contract can rebuild rulesHash", async () => {
      const [hi, lo] = await harness.read.toLimbs([hash]);
      assert.ok(hi < 1n << 128n);
      assert.ok(lo < 1n << 128n);
      assert.equal(await harness.read.fromLimbs([hi, lo]), hash);
    });

    it("rejects an oversized limb rather than silently truncating", async () => {
      await assert.rejects(
        () => harness.read.fromLimbs([1n << 128n, 0n]),
        /LimbExceeds128Bits/,
      );
    });
  });

  describe("tenderIdField (spec Section 5)", () => {
    it("matches the frozen value for the Figure 5 demo tender", async () => {
      assert.equal(
        await harness.read.tenderIdField([VECTOR.tenderId]),
        EXPECTED.tenderIdField,
      );
    });

    it("is distinct per tender, preventing cross-tender replay", async () => {
      const a = await harness.read.tenderIdField(["FP-00014"]);
      const b = await harness.read.tenderIdField(["FP-00015"]);
      assert.notEqual(a, b);
    });
  });

  describe("Poseidon (spec Section 7)", () => {
    it("matches the circomlib reference vector for Poseidon(1,2)", async () => {
      // If this fails, poseidon-solidity's constants differ from circomlib's
      // and every on-chain root would disagree with every circuit.
      assert.equal(
        await harness.read.hash2([1n, 2n]),
        EXPECTED.poseidon2_1_2,
      );
    });
  });

  describe("bid leaf and accumulator (spec Section 12)", () => {
    it("the bid leaf matches TypeScript and Circom", async () => {
      assert.equal(
        await harness.read.bidLeaf([
          EXPECTED.nullifier,
          EXPECTED.bidCommitment,
          VECTOR.ciphertextHashField,
          VECTOR.submissionIndex,
        ]),
        EXPECTED.bidLeaf,
      );
    });

    it("the empty-tree root matches TypeScript and Circom", async () => {
      assert.equal(await harness.read.emptyRoot(), EXPECTED.emptyRoot);
    });

    it("a one-leaf tree matches the TypeScript accumulator", async () => {
      // Rebuild the root the way the contract will: leaf at index 0, every
      // right sibling an empty subtree of the padding leaf.
      let zero = DOMAIN_PADDING_V1;
      let node = EXPECTED.bidLeaf;
      for (let d = 0; d < 5; d++) {
        node = await harness.read.hash2([node, zero]);
        zero = await harness.read.hash2([zero, zero]);
      }
      assert.equal(node, EXPECTED.oneLeafRoot);
    });

    it("the padding leaf is not zero", async () => {
      // A zero leaf is indistinguishable from an empty subtree and would
      // permit a completeness bypass (whitepaper Section 7).
      assert.notEqual(DOMAIN_PADDING_V1, 0n);
      assert.notEqual(await harness.read.emptyRoot(), 0n);
    });
  });

  describe("gas cost of on-chain Poseidon (plan Section 13.1)", () => {
    it("reports measured gas for the benchmark record", async () => {
      const h2 = await harness.read.measureHash2Gas([1n, 2n]);
      const leafGas = await harness.read.measureBidLeafGas([
        EXPECTED.nullifier,
        EXPECTED.bidCommitment,
        VECTOR.ciphertextHashField,
        VECTOR.submissionIndex,
      ]);
      // Recorded, not asserted against a target: whitepaper Table 15 commits
      // to measured values, not design targets.
      console.log(`      hash2 tx gas:   ${h2}`);
      console.log(`      bidLeaf tx gas: ${leafGas}`);
    });
  });
});
