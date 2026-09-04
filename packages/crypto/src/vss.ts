/**
 * Feldman verifiable secret sharing for the tender opening committee.
 *
 * Development plan Section 12.2, whitepaper Section 6: 3-of-5 threshold
 * opening. This is the OPENING threshold and has nothing to do with the
 * 2-of-3 storage-replica quorum; the two are separate mechanisms with
 * separate constants (docs/cryptography.md Section 6).
 *
 * WHAT THIS DOES AND DOES NOT PROTECT AGAINST.
 *
 * Feldman VSS makes the DEALING publicly verifiable. The dealer publishes
 * commitments C_0..C_{t-1} to its polynomial's coefficients, and anyone -
 * a member checking their own share, or the tender contract - can confirm
 * that a share is the correct evaluation of the committed polynomial. So a
 * dealer cannot hand out inconsistent shares and later blame a member for a
 * failed opening, and cannot claim a public key that does not correspond to
 * the shares it dealt.
 *
 * It does NOT hide the secret from the dealer. This is a trusted-dealer
 * ceremony: the dealer knows `x` for the duration of the script and then
 * destroys it. Whitepaper Section 19.1 concedes that full DKG is production
 * design until implemented. Label it as such everywhere the threshold is
 * displayed - "verifiable threshold opening with a trusted dealer
 * (prototype); production requires DKG".
 *
 * THE BIDDER IS DELIBERATELY NOT THE DEALER. An earlier design had each
 * bidder split its own data-encryption key. A bidder acting as its own dealer
 * can hand out inconsistent shares and make its own bid permanently
 * un-openable, which breaks the completeness the award proof depends on and
 * gives a losing bidder a way to invalidate the tender. The committee key is
 * therefore dealt once, at tender activation, for all bids.
 */
import {
  BASE8,
  IDENTITY,
  SUB_ORDER,
  addPoint,
  inCurve,
  invModSubOrder,
  isInPrimeSubgroup,
  mulBase,
  mulPoint,
  pointsEqual,
  type Point,
} from "./babyjub.js";
import { COMMITTEE_SIZE, COMMITTEE_THRESHOLD } from "./domains.js";

/** One member's share of the tender secret. */
export interface CommitteeShare {
  /** 1-based. Index 0 would be the secret itself, so it is never a member. */
  index: number;
  /** The secret share f(index). NEVER log, transmit or persist unencrypted. */
  share: bigint;
  /** Y_i = share * G. Public, and stored on-chain for DLEQ verification. */
  publicShare: Point;
}

/** The result of dealing a tender committee key. */
export interface DealtCommitteeKey {
  threshold: number;
  size: number;
  /** The tender secret x. The dealer destroys this; it is never published. */
  secret: bigint;
  /** Y = x * G. Bidders encrypt to this. */
  publicKey: Point;
  /** Feldman commitments C_j = a_j * G, with C_0 == Y. */
  commitments: Point[];
  shares: CommitteeShare[];
}

/**
 * A cryptographically secure scalar in [1, SUB_ORDER).
 *
 * Rejection sampling rather than `mod SUB_ORDER` on a 256-bit draw: the
 * modulo would bias the low end of the range. The bias is small, but a
 * biased secret key is exactly the kind of defect that is invisible in tests
 * and fatal in aggregate.
 */
export function randomScalar(): bigint {
  const bytes = new Uint8Array(32);
  for (;;) {
    crypto.getRandomValues(bytes);
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    if (v > 0n && v < SUB_ORDER) return v;
  }
}

/**
 * Deal a threshold key with Feldman VSS.
 *
 * @param secret Supply only for deterministic tests. Production and the
 *        ceremony script must let this be generated here.
 */
export function dealCommitteeKey(params: {
  threshold?: number;
  size?: number;
  secret?: bigint;
  coefficients?: bigint[];
} = {}): DealtCommitteeKey {
  const threshold = params.threshold ?? COMMITTEE_THRESHOLD;
  const size = params.size ?? COMMITTEE_SIZE;
  if (threshold < 2) throw new Error("dealCommitteeKey: a threshold below 2 is not a threshold");
  if (threshold > size) throw new Error("dealCommitteeKey: threshold exceeds committee size");

  const secret = params.secret ?? randomScalar();
  if (secret <= 0n || secret >= SUB_ORDER) {
    throw new Error("dealCommitteeKey: the secret must lie in [1, SUB_ORDER)");
  }

  // f(z) = a_0 + a_1 z + ... + a_{t-1} z^{t-1}, with a_0 = the secret.
  const coefficients = params.coefficients
    ? [secret, ...params.coefficients]
    : [secret, ...Array.from({ length: threshold - 1 }, randomScalar)];
  if (coefficients.length !== threshold) {
    throw new Error(
      `dealCommitteeKey: expected ${threshold - 1} extra coefficients, got ${coefficients.length - 1}`,
    );
  }

  const commitments = coefficients.map(mulBase);
  const publicKey = commitments[0];

  const shares: CommitteeShare[] = [];
  for (let i = 1; i <= size; i++) {
    const share = evaluatePolynomial(coefficients, BigInt(i));
    shares.push({ index: i, share, publicShare: mulBase(share) });
  }

  return { threshold, size, secret, publicKey, commitments, shares };
}

/** f(z) mod SUB_ORDER by Horner's rule. */
export function evaluatePolynomial(coefficients: bigint[], z: bigint): bigint {
  let acc = 0n;
  for (let i = coefficients.length - 1; i >= 0; i--) {
    acc = (acc * z + coefficients[i]) % SUB_ORDER;
  }
  return acc;
}

/**
 * The public share a correct dealer must have produced for `index`:
 *
 *     Y_i = sum_j (i^j) * C_j
 *
 * This is the whole content of Feldman's verifiability. It is computed on
 * chain as well, in `BabyJubjub.expectedPublicShare`, so the tender contract
 * enforces it rather than relying on members to check.
 */
export function expectedPublicShare(index: number, commitments: Point[]): Point {
  if (index < 1) throw new Error("expectedPublicShare: member indices are 1-based");
  let acc: Point = { ...IDENTITY };
  let power = 1n;
  for (const c of commitments) {
    acc = addPoint(acc, mulPoint(c, power));
    power = (power * BigInt(index)) % SUB_ORDER;
  }
  return acc;
}

/** Whether a share really is the committed polynomial's value at `index`. */
export function verifyShare(
  share: CommitteeShare,
  commitments: Point[],
): boolean {
  if (share.share <= 0n || share.share >= SUB_ORDER) return false;
  if (!pointsEqual(mulBase(share.share), share.publicShare)) return false;
  return pointsEqual(share.publicShare, expectedPublicShare(share.index, commitments));
}

/**
 * Every check the tender contract performs, run off-chain first.
 *
 * The dealer script calls this before printing any on-chain arguments, so a
 * bad dealing fails at the desk instead of in a transaction whose revert
 * reason has to be decoded.
 */
export function verifyDealing(dealt: DealtCommitteeKey): { ok: boolean; problems: string[] } {
  const problems: string[] = [];

  if (dealt.commitments.length !== dealt.threshold) {
    problems.push(
      `expected ${dealt.threshold} commitments, got ${dealt.commitments.length}`,
    );
  }
  dealt.commitments.forEach((c, j) => {
    if (!inCurve(c)) problems.push(`commitment C_${j} is not on the curve`);
  });

  // C_0 IS the public key. If these differed, bidders would encrypt to a key
  // the shares cannot open.
  if (!pointsEqual(dealt.publicKey, dealt.commitments[0])) {
    problems.push("publicKey does not equal commitment C_0");
  }
  if (!isInPrimeSubgroup(dealt.publicKey)) {
    problems.push("publicKey is not in the prime-order subgroup");
  }

  if (dealt.shares.length !== dealt.size) {
    problems.push(`expected ${dealt.size} shares, got ${dealt.shares.length}`);
  }
  const seen = new Set<number>();
  let indicesUsable = dealt.shares.length >= dealt.threshold;
  for (const s of dealt.shares) {
    if (seen.has(s.index)) {
      problems.push(`duplicate share index ${s.index}`);
      indicesUsable = false;
    }
    seen.add(s.index);
    if (!verifyShare(s, dealt.commitments)) {
      problems.push(`share ${s.index} does not match the commitments`);
    }
  }

  // Reconstruction from the first `threshold` shares must return the secret.
  // Feldman verifies the dealing; this verifies that the dealing is USABLE,
  // which is a different claim and the one completeness depends on.
  //
  // Skipped when the index set is already malformed: Lagrange interpolation
  // is undefined over duplicate indices, so attempting it would throw and
  // hide the list of problems this function exists to report.
  if (indicesUsable) {
    const subset = dealt.shares.slice(0, dealt.threshold);
    if (reconstructSecret(subset) !== dealt.secret % SUB_ORDER) {
      problems.push("the first t shares do not reconstruct the secret");
    }
  }

  return { ok: problems.length === 0, problems };
}

/**
 * Lagrange coefficient for `index` over `indices`, at z = 0, mod SUB_ORDER.
 *
 * Modulo SUB_ORDER, not the field prime: the exponents live in the scalar
 * field of the prime-order subgroup. Using the wrong modulus produces shares
 * that verify individually and then reconstruct to the wrong secret, which is
 * a genuinely hard failure to diagnose.
 */
export function lagrangeCoefficient(indices: number[], index: number): bigint {
  if (!indices.includes(index)) {
    throw new Error(`lagrangeCoefficient: ${index} is not in the index set`);
  }
  if (new Set(indices).size !== indices.length) {
    throw new Error("lagrangeCoefficient: duplicate indices");
  }
  let numerator = 1n;
  let denominator = 1n;
  for (const j of indices) {
    if (j === index) continue;
    numerator = (numerator * BigInt(j)) % SUB_ORDER;
    const diff = (BigInt(j) - BigInt(index) + SUB_ORDER) % SUB_ORDER;
    denominator = (denominator * diff) % SUB_ORDER;
  }
  return (numerator * invModSubOrder(denominator)) % SUB_ORDER;
}

/**
 * Reconstruct the secret from at least `threshold` shares.
 *
 * Used by the ceremony's own self-check and by tests. The live opening path
 * does NOT do this: it interpolates in the EXPONENT (`combineInExponent`) so
 * the tender secret is never reassembled anywhere. Reconstructing the scalar
 * would defeat the point of the threshold.
 */
export function reconstructSecret(shares: CommitteeShare[]): bigint {
  const indices = shares.map((s) => s.index);
  let acc = 0n;
  for (const s of shares) {
    acc = (acc + s.share * lagrangeCoefficient(indices, s.index)) % SUB_ORDER;
  }
  return acc;
}

/**
 * Interpolate decryption shares in the exponent: S = sum_i lambda_i * D_i.
 *
 * With D_i = x_i * R, this yields x * R without any party learning x. This is
 * the operation the opening ceremony actually performs.
 */
export function combineInExponent(
  parts: { index: number; point: Point }[],
): Point {
  const indices = parts.map((p) => p.index);
  let acc: Point = { ...IDENTITY };
  for (const p of parts) {
    acc = addPoint(acc, mulPoint(p.point, lagrangeCoefficient(indices, p.index)));
  }
  return acc;
}
