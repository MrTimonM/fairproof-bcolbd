/**
 * Emit BabyJubjub reference vectors from circomlibjs for the Solidity test.
 */
import { writeFileSync } from "node:fs";
import {
  BASE8, CURVE_PRIME, IDENTITY, SUB_ORDER,
  addPoint, dealCommitteeKey, expectedPublicShare, initBabyjub, mulBase, mulPoint,
} from "@fairproof/crypto";

await initBabyjub();

const SECRET = 1234567890123456789012345678901234567890123456789n % SUB_ORDER;
const COEFFS = [
  9876543210987654321098765432109876543210987654321n % SUB_ORDER,
  1111111111222222222233333333334444444444555555555n % SUB_ORDER,
];
const dealt = dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });
const s = (p) => ({ x: p.x.toString(), y: p.y.toString() });

const scalars = [1n, 2n, 3n, 5n, 25n, 1000n, 123456789n, SUB_ORDER - 1n];

writeFileSync(
  "packages/contracts/test/fixtures/babyjubjub-vectors.json",
  JSON.stringify(
    {
      $comment:
        "Generated from circomlibjs by scripts/gen-babyjubjub-vectors.mjs. " +
        "The Solidity BabyJubjub library must reproduce every value here. " +
        "Regenerate only if circomlibjs changes; a diff means the two " +
        "implementations have diverged and the circuit will disagree too.",
      prime: CURVE_PRIME.toString(),
      subOrder: SUB_ORDER.toString(),
      base8: s(BASE8),
      identity: s(IDENTITY),
      mulBase: scalars.map((e) => ({ scalar: e.toString(), point: s(mulBase(e)) })),
      additions: [
        { a: s(mulBase(3n)), b: s(mulBase(7n)), sum: s(addPoint(mulBase(3n), mulBase(7n))) },
        { a: s(mulBase(11n)), b: s(mulBase(11n)), sum: s(addPoint(mulBase(11n), mulBase(11n))) },
        { a: s(mulBase(5n)), b: s(IDENTITY), sum: s(addPoint(mulBase(5n), IDENTITY)) },
        { a: s(IDENTITY), b: s(IDENTITY), sum: s(addPoint(IDENTITY, IDENTITY)) },
      ],
      mulPoint: [
        { point: s(mulBase(9n)), scalar: "13", product: s(mulPoint(mulBase(9n), 13n)) },
      ],
      offCurve: [
        { x: "1", y: "1" },
        { x: "0", y: "0" },
        { x: CURVE_PRIME.toString(), y: "1" },
      ],
      onCurveButNotSubgroup: [{ x: "0", y: (CURVE_PRIME - 1n).toString() }],
      committee: {
        threshold: dealt.threshold,
        size: dealt.size,
        publicKey: s(dealt.publicKey),
        commitments: dealt.commitments.map(s),
        shares: dealt.shares.map((sh) => ({
          index: sh.index,
          share: sh.share.toString(),
          publicShare: s(sh.publicShare),
        })),
        expectedPublicShares: dealt.shares.map((sh) => ({
          index: sh.index,
          point: s(expectedPublicShare(sh.index, dealt.commitments)),
        })),
      },
    },
    null,
    2,
  ) + "\n",
);
console.log("wrote packages/contracts/test/fixtures/babyjubjub-vectors.json");
