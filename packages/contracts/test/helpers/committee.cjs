const { readFileSync } = require("node:fs");
const { join } = require("node:path");

/**
 * The 3-of-5 Feldman committee key from the shared eligibility fixture.
 *
 * `TenderRegistry.setCommitteeKey` verifies the dealing on-chain, so a test
 * can no longer pass arbitrary large numbers as curve points. Earlier
 * versions of these tests did exactly that: the values were structurally
 * plausible, every assertion passed, and nothing in the suite would have
 * noticed that the committee key was not a point on BabyJubjub at all.
 *
 * This key is the one the fixture's sealed ciphertexts are encrypted to, so
 * the tender the contract tests activate is the tender those ciphertexts
 * belong to - which is what lets the opening tests actually open them.
 *
 * Regenerate with `npm run fixtures:eligibility`.
 */
const FIX = JSON.parse(
  readFileSync(
    join(__dirname, "../../../circuits/fixtures/eligibility.proof.json"),
    "utf8",
  ),
);

const C = FIX.committee;

const publicKey = { x: BigInt(C.publicKey.x), y: BigInt(C.publicKey.y) };

/**
 * The trailing arguments of `setCommitteeKey`, given the five member
 * addresses: (members, memberX, memberY, commitmentX, commitmentY).
 */
function committeeArgs(memberAddresses) {
  if (memberAddresses.length !== C.size) {
    throw new Error(`expected ${C.size} committee members`);
  }
  return [
    memberAddresses,
    C.shares.map((s) => BigInt(s.publicShare.x)),
    C.shares.map((s) => BigInt(s.publicShare.y)),
    C.commitments.map((c) => BigInt(c.x)),
    C.commitments.map((c) => BigInt(c.y)),
  ];
}

/** Curve edge cases, from the BabyJubjub reference vectors. */
const V = JSON.parse(
  readFileSync(join(__dirname, "../fixtures/babyjubjub-vectors.json"), "utf8"),
);

module.exports = {
  publicKey,
  committeeArgs,
  commitments: C.commitments,
  shares: C.shares,
  threshold: C.threshold,
  size: C.size,
  sealed: FIX.sealed,
  base8: V.base8,
  identity: V.identity,
  prime: BigInt(V.prime),
  subOrder: BigInt(V.subOrder),
  offCurve: V.offCurve,
  onCurveButNotSubgroup: V.onCurveButNotSubgroup,
};
