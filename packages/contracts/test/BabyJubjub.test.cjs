const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const hre = require("hardhat");

/**
 * BabyJubjub in Solidity, checked against circomlibjs.
 *
 * Development plan Section 13.1's rule, applied to curve arithmetic rather
 * than to Poseidon: "the identical parameters must be used in Circom, in
 * TypeScript, and in Solidity... If this test does not exist, assume the
 * three disagree."
 *
 * The vectors come from `node scripts/gen-babyjubjub-vectors.mjs`, which reads
 * circomlibjs - the same library the circuits use. A divergence here means the
 * contract and the circuit would disagree about what a public key is, and the
 * symptom would be a reverted `setCommitteeKey` with no indication which
 * operation was wrong.
 */
const V = JSON.parse(
  readFileSync(join(__dirname, "fixtures/babyjubjub-vectors.json"), "utf8"),
);

describe("BabyJubjub (Solidity vs circomlibjs)", function () {
  this.timeout(180000);

  let jub;

  before(async () => {
    jub = await hre.viem.deployContract("BabyJubjubHarness", []);
  });

  it("agrees on the field prime and the subgroup order", async () => {
    assert.equal(await jub.read.prime(), BigInt(V.prime));
    assert.equal(await jub.read.subOrder(), BigInt(V.subOrder));
  });

  it("the generator is on the curve and in the prime-order subgroup", async () => {
    const { x, y } = V.base8;
    assert.equal(await jub.read.inCurve([BigInt(x), BigInt(y)]), true);
    assert.equal(await jub.read.isInPrimeSubgroup([BigInt(x), BigInt(y)]), true);
  });

  it("reproduces every scalar multiple of the generator", async () => {
    for (const { scalar, point } of V.mulBase) {
      const [x, y] = await jub.read.mulBase([BigInt(scalar)]);
      assert.equal(x, BigInt(point.x), `mulBase(${scalar}).x`);
      assert.equal(y, BigInt(point.y), `mulBase(${scalar}).y`);
    }
  });

  it("reproduces every addition, including doubling and the identity", async () => {
    // The doubling case is the one worth naming: the addition law here is
    // unified, so P + P must come out right with no separate branch.
    for (const { a, b, sum } of V.additions) {
      const [x, y] = await jub.read.add([
        BigInt(a.x), BigInt(a.y), BigInt(b.x), BigInt(b.y),
      ]);
      assert.equal(x, BigInt(sum.x));
      assert.equal(y, BigInt(sum.y));
    }
  });

  it("reproduces scalar multiplication of a non-generator point", async () => {
    for (const { point, scalar, product } of V.mulPoint) {
      const [x, y] = await jub.read.mul([
        BigInt(point.x), BigInt(point.y), BigInt(scalar),
      ]);
      assert.equal(x, BigInt(product.x));
      assert.equal(y, BigInt(product.y));
    }
  });

  it("SUB_ORDER * G is the identity", async () => {
    const [x, y] = await jub.read.mulBase([BigInt(V.subOrder)]);
    assert.equal(x, BigInt(V.identity.x));
    assert.equal(y, BigInt(V.identity.y));
  });

  it("rejects points that are not on the curve", async () => {
    for (const p of V.offCurve) {
      assert.equal(
        await jub.read.inCurve([BigInt(p.x), BigInt(p.y)]),
        false,
        `(${p.x}, ${p.y}) must be rejected`,
      );
    }
  });

  it("subgroup membership is strictly stronger than curve membership", async () => {
    // (0, -1) satisfies the curve equation and has order 2. Accepting it as a
    // tender public key would let a bidder encrypt to a leaky key, which is
    // the entire reason isInPrimeSubgroup exists alongside inCurve.
    for (const p of V.onCurveButNotSubgroup) {
      assert.equal(await jub.read.inCurve([BigInt(p.x), BigInt(p.y)]), true);
      assert.equal(await jub.read.isInPrimeSubgroup([BigInt(p.x), BigInt(p.y)]), false);
    }
  });

  it("computes the Feldman expected public share for every member", async () => {
    // The check that makes a dishonest dealer detectable ON-CHAIN rather than
    // only by a member inspecting their own share.
    const cx = V.committee.commitments.map((c) => BigInt(c.x));
    const cy = V.committee.commitments.map((c) => BigInt(c.y));
    for (const e of V.committee.expectedPublicShares) {
      const [x, y] = await jub.read.expectedPublicShare([cx, cy, BigInt(e.index)]);
      assert.equal(x, BigInt(e.point.x), `member ${e.index} x`);
      assert.equal(y, BigInt(e.point.y), `member ${e.index} y`);
    }
  });

  it("the expected public shares equal the dealer's published ones", async () => {
    const cx = V.committee.commitments.map((c) => BigInt(c.x));
    const cy = V.committee.commitments.map((c) => BigInt(c.y));
    for (const s of V.committee.shares) {
      const [x, y] = await jub.read.expectedPublicShare([cx, cy, BigInt(s.index)]);
      assert.equal(x, BigInt(s.publicShare.x));
      assert.equal(y, BigInt(s.publicShare.y));
    }
  });

  it("C_0 is the committee public key", async () => {
    assert.equal(V.committee.commitments[0].x, V.committee.publicKey.x);
    assert.equal(V.committee.commitments[0].y, V.committee.publicKey.y);
  });

  it("reports measured gas for the subgroup check", async () => {
    // The most expensive operation in the library: a 251-bit scalar
    // multiplication. Recorded because it is paid once per tender at
    // activation, and because a number nobody measured is a number nobody
    // can defend.
    const client = await hre.viem.getPublicClient();
    const gas = await client.estimateContractGas({
      address: jub.address,
      abi: jub.abi,
      functionName: "isInPrimeSubgroup",
      args: [BigInt(V.base8.x), BigInt(V.base8.y)],
    });
    console.log(`      isInPrimeSubgroup: ${gas} gas`);
    assert.ok(gas > 50000n, "a 251-bit scalar multiplication cannot be this cheap");
  });
});
