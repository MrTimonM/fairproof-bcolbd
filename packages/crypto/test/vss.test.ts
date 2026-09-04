import { beforeAll, describe, expect, it } from "vitest";
import {
  BASE8,
  CURVE_PRIME,
  COMMITTEE_SIZE,
  COMMITTEE_THRESHOLD,
  IDENTITY,
  SUB_ORDER,
  addPoint,
  combineInExponent,
  dealCommitteeKey,
  evaluatePolynomial,
  expectedPublicShare,
  inCurve,
  initBabyjub,
  invModSubOrder,
  isInPrimeSubgroup,
  lagrangeCoefficient,
  mulBase,
  mulPoint,
  negatePoint,
  pointsEqual,
  randomScalar,
  reconstructSecret,
  verifyDealing,
  verifyShare,
} from "../src/index.js";

/**
 * Feldman VSS for the 3-of-5 opening committee.
 *
 * Whitepaper Section 6, development plan Section 12.2. The negative tests
 * matter most: a threshold scheme that accepts a bad share, or that opens
 * with two shares, is worse than no threshold at all, because it is described
 * as one.
 */

// Deterministic for reproducibility. Production draws from randomScalar().
const SECRET = 1234567890123456789012345678901234567890123456789n % SUB_ORDER;
const COEFFS = [
  9876543210987654321098765432109876543210987654321n % SUB_ORDER,
  1111111111222222222233333333334444444444555555555n % SUB_ORDER,
];

beforeAll(async () => {
  await initBabyjub();
});

describe("BabyJubjub arithmetic", () => {
  it("the generator is on the curve and in the prime-order subgroup", () => {
    expect(inCurve(BASE8)).toBe(true);
    expect(isInPrimeSubgroup(BASE8)).toBe(true);
  });

  it("SUB_ORDER * G is the identity", () => {
    expect(pointsEqual(mulPoint(BASE8, SUB_ORDER), IDENTITY)).toBe(true);
  });

  it("scalar multiplication is additive in the exponent", () => {
    const a = 7654321n;
    const b = 1234567n;
    expect(pointsEqual(mulBase(a + b), addPoint(mulBase(a), mulBase(b)))).toBe(true);
  });

  it("negation cancels", () => {
    const p = mulBase(424242n);
    expect(pointsEqual(addPoint(p, negatePoint(p)), IDENTITY)).toBe(true);
  });

  it("rejects a point that is not on the curve", () => {
    expect(inCurve({ x: 1n, y: 1n })).toBe(false);
  });

  it("rejects coordinates at or above the field prime", () => {
    expect(inCurve({ x: CURVE_PRIME, y: 1n })).toBe(false);
    expect(inCurve({ x: 0n, y: CURVE_PRIME + 1n })).toBe(false);
  });

  it("subgroup membership is strictly stronger than curve membership", () => {
    // (0, -1) satisfies the curve equation and has order 2, so it is a
    // curve point that is NOT in the prime-order subgroup. This is exactly
    // why the tender public key gets a subgroup check and not just inCurve.
    const orderTwo = { x: 0n, y: CURVE_PRIME - 1n };
    expect(inCurve(orderTwo)).toBe(true);
    expect(isInPrimeSubgroup(orderTwo)).toBe(false);
  });

  it("inverts modulo SUB_ORDER", () => {
    for (const v of [1n, 2n, 3n, 12345n, SUB_ORDER - 1n]) {
      expect((v * invModSubOrder(v)) % SUB_ORDER).toBe(1n);
    }
  });

  it("refuses to invert zero", () => {
    expect(() => invModSubOrder(0n)).toThrow(/not invertible/);
  });

  it("randomScalar stays inside [1, SUB_ORDER)", () => {
    for (let i = 0; i < 50; i++) {
      const s = randomScalar();
      expect(s > 0n).toBe(true);
      expect(s < SUB_ORDER).toBe(true);
    }
  });
});

describe("dealing a 3-of-5 committee key", () => {
  const dealt = () =>
    dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });

  it("uses the whitepaper's 3-of-5, not some other threshold", () => {
    const d = dealt();
    expect(COMMITTEE_THRESHOLD).toBe(3);
    expect(COMMITTEE_SIZE).toBe(5);
    expect(d.threshold).toBe(3);
    expect(d.size).toBe(5);
    expect(d.shares).toHaveLength(5);
    expect(d.commitments).toHaveLength(3);
  });

  it("commits to the public key as C_0", () => {
    const d = dealt();
    expect(pointsEqual(d.publicKey, d.commitments[0])).toBe(true);
    expect(pointsEqual(d.publicKey, mulBase(SECRET))).toBe(true);
  });

  it("passes every check the contract will perform", () => {
    const { ok, problems } = verifyDealing(dealt());
    expect(problems).toEqual([]);
    expect(ok).toBe(true);
  });

  it("every share matches the published commitments", () => {
    const d = dealt();
    for (const s of d.shares) {
      expect(verifyShare(s, d.commitments)).toBe(true);
      expect(pointsEqual(s.publicShare, expectedPublicShare(s.index, d.commitments))).toBe(true);
    }
  });

  it("members are 1-based, so no member holds the secret itself", () => {
    const d = dealt();
    expect(d.shares.map((s) => s.index)).toEqual([1, 2, 3, 4, 5]);
    // f(0) is the secret; if a member had index 0, that member alone could open.
    expect(evaluatePolynomial([SECRET, ...COEFFS], 0n)).toBe(SECRET);
  });

  it("two different dealings produce different keys", () => {
    const a = dealCommitteeKey();
    const b = dealCommitteeKey();
    expect(pointsEqual(a.publicKey, b.publicKey)).toBe(false);
  });

  it("rejects a threshold below 2", () => {
    expect(() => dealCommitteeKey({ threshold: 1, size: 5 })).toThrow(/not a threshold/);
  });

  it("rejects a threshold above the committee size", () => {
    expect(() => dealCommitteeKey({ threshold: 6, size: 5 })).toThrow(/exceeds committee size/);
  });

  it("rejects a secret outside [1, SUB_ORDER)", () => {
    expect(() => dealCommitteeKey({ secret: 0n })).toThrow(/must lie in/);
    expect(() => dealCommitteeKey({ secret: SUB_ORDER })).toThrow(/must lie in/);
  });
});

describe("a tampered dealing is detected", () => {
  it("a modified share fails verification", () => {
    const d = dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });
    const bad = { ...d.shares[2], share: d.shares[2].share + 1n };
    expect(verifyShare(bad, d.commitments)).toBe(false);
  });

  it("a share moved to another member's index fails", () => {
    // The attack Feldman stops: a dealer handing member 4 member 3's share,
    // or a member claiming someone else's share as their own.
    const d = dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });
    const moved = { ...d.shares[2], index: 4 };
    expect(verifyShare(moved, d.commitments)).toBe(false);
  });

  it("a public share inconsistent with its secret share fails", () => {
    const d = dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });
    const bad = { ...d.shares[0], publicShare: d.shares[1].publicShare };
    expect(verifyShare(bad, d.commitments)).toBe(false);
  });

  it("a dealing whose public key does not match C_0 is rejected", () => {
    const d = dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });
    const forged = { ...d, publicKey: mulBase(999n) };
    const { ok, problems } = verifyDealing(forged);
    expect(ok).toBe(false);
    expect(problems.join(" ")).toMatch(/does not equal commitment C_0/);
  });

  it("a dealing with inconsistent shares is rejected as unusable", () => {
    const d = dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });
    const tampered = {
      ...d,
      shares: d.shares.map((s, i) => (i === 1 ? { ...s, share: s.share + 5n } : s)),
    };
    const { ok, problems } = verifyDealing(tampered);
    expect(ok).toBe(false);
    expect(problems.join(" ")).toMatch(/share 2 does not match/);
  });

  it("a duplicate share index is rejected", () => {
    const d = dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });
    const dup = { ...d, shares: [d.shares[0], d.shares[0], ...d.shares.slice(2)] };
    const { ok, problems } = verifyDealing(dup);
    expect(ok).toBe(false);
    expect(problems.join(" ")).toMatch(/duplicate share index/);
  });
});

describe("reconstruction requires exactly the threshold", () => {
  const d = () => dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });

  it("any three shares reconstruct the secret", () => {
    const dealt = d();
    const subsets = [
      [0, 1, 2],
      [0, 2, 4],
      [1, 3, 4],
      [2, 3, 4],
    ];
    for (const idx of subsets) {
      const shares = idx.map((i) => dealt.shares[i]);
      expect(reconstructSecret(shares)).toBe(SECRET % SUB_ORDER);
    }
  });

  it("TWO shares do not reconstruct the secret", () => {
    // The check that distinguishes a real threshold from a description of
    // one. Whitepaper Section 6 and the demo's 1/3 then 2/3 meter.
    const dealt = d();
    const two = reconstructSecret([dealt.shares[0], dealt.shares[1]]);
    expect(two).not.toBe(SECRET % SUB_ORDER);
  });

  it("ONE share does not reconstruct the secret", () => {
    const dealt = d();
    expect(reconstructSecret([dealt.shares[0]])).not.toBe(SECRET % SUB_ORDER);
  });

  it("all five shares also reconstruct it", () => {
    expect(reconstructSecret(d().shares)).toBe(SECRET % SUB_ORDER);
  });

  it("Lagrange coefficients at z=0 sum to one", () => {
    const indices = [2, 3, 5];
    const sum = indices.reduce(
      (acc, i) => (acc + lagrangeCoefficient(indices, i)) % SUB_ORDER,
      0n,
    );
    expect(sum).toBe(1n);
  });

  it("rejects duplicate or absent indices", () => {
    expect(() => lagrangeCoefficient([1, 1, 2], 1)).toThrow(/duplicate/);
    expect(() => lagrangeCoefficient([1, 2, 3], 4)).toThrow(/not in the index set/);
  });
});

describe("interpolation in the exponent (the live opening path)", () => {
  /**
   * The opening ceremony never reassembles the tender secret. Each member
   * publishes D_i = x_i * R and the application combines those points. These
   * tests confirm the combination yields x * R without x existing anywhere.
   */
  // Lazy: describe bodies run at collection time, before beforeAll has
  // initialised the curve.
  const ephemeral = () => mulBase(55555555n);

  it("three decryption shares combine to x * R", () => {
    const d = dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });
    const parts = [0, 2, 4].map((i) => ({
      index: d.shares[i].index,
      point: mulPoint(ephemeral(), d.shares[i].share),
    }));
    expect(pointsEqual(combineInExponent(parts), mulPoint(ephemeral(), SECRET))).toBe(true);
  });

  it("the result is independent of WHICH three members participate", () => {
    const d = dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });
    const target = mulPoint(ephemeral(), SECRET);
    for (const idx of [[0, 1, 2], [1, 2, 3], [0, 3, 4], [2, 3, 4]]) {
      const parts = idx.map((i) => ({
        index: d.shares[i].index,
        point: mulPoint(ephemeral(), d.shares[i].share),
      }));
      expect(pointsEqual(combineInExponent(parts), target)).toBe(true);
    }
  });

  it("TWO decryption shares do not recover x * R", () => {
    const d = dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });
    const parts = [0, 1].map((i) => ({
      index: d.shares[i].index,
      point: mulPoint(ephemeral(), d.shares[i].share),
    }));
    expect(pointsEqual(combineInExponent(parts), mulPoint(ephemeral(), SECRET))).toBe(false);
  });

  it("one forged decryption share corrupts the result rather than being ignored", () => {
    // Why the on-chain DLEQ proof exists: without it a member could submit a
    // wrong point and the combination would silently produce garbage, which
    // then fails as an AES tag error and looks like a bidder's fault.
    const d = dealCommitteeKey({ secret: SECRET, coefficients: COEFFS });
    const parts = [0, 2, 4].map((i, n) => ({
      index: d.shares[i].index,
      point: n === 1
          ? mulPoint(ephemeral(), d.shares[i].share + 1n)
          : mulPoint(ephemeral(), d.shares[i].share),
    }));
    expect(pointsEqual(combineInExponent(parts), mulPoint(ephemeral(), SECRET))).toBe(false);
  });
});
