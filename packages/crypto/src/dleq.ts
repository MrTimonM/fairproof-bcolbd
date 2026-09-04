/**
 * Chaum-Pedersen proofs of discrete-logarithm equality.
 *
 * Whitepaper Section 6, development plan Section 12.6 step 4, encoding spec
 * Section 21.
 *
 * WHY THIS EXISTS. A committee member's decryption share D_i = x_i * R is just
 * a curve point. Without a proof, a member could publish any point at all and
 * the combination would produce garbage - which then surfaces as an AES-GCM
 * tag failure and looks like the BIDDER's fault. The plan is explicit that
 * "an invalid share is rejected and attributed, not silently dropped", and
 * attribution is only possible if the share carries a proof that it came from
 * the holder of the published Y_i.
 *
 * The proof shows log_G(Y_i) = log_R(D_i) without revealing x_i, and it is
 * verified ON-CHAIN, so rejection and attribution are public facts rather
 * than an application's opinion.
 */
import { getBytes, keccak256 } from "ethers";
import {
  BASE8,
  SUB_ORDER,
  addPoint,
  inCurve,
  mulBase,
  mulPoint,
  pointsEqual,
  type Point,
} from "./babyjub.js";
import { RAW_DLEQ_V1 } from "./domains.js";
import { concatBytes, toBytes } from "./field.js";
import { randomScalar } from "./vss.js";

/** A Chaum-Pedersen proof. `a` and `b` are the commitments, `z` the response. */
export interface DleqProof {
  a: Point;
  b: Point;
  z: bigint;
}

/**
 * The Fiat-Shamir challenge. Spec Section 21.
 *
 * Covers BOTH statements and BOTH commitments. Omitting R or D would let a
 * proof produced for one ciphertext be replayed against another, which is the
 * whole attack this construction has to prevent - a member could prove once
 * and have that proof accepted for every bid in the tender.
 */
export function dleqChallenge(params: {
  publicShare: Point; // Y_i = x_i * G
  ephemeral: Point; // R
  decryptionShare: Point; // D_i = x_i * R
  commitmentA: Point; // A = w * G
  commitmentB: Point; // B = w * R
}): bigint {
  const p = params;
  const preimage = concatBytes(
    getBytes(RAW_DLEQ_V1),
    toBytes(BASE8.x, 32),
    toBytes(BASE8.y, 32),
    toBytes(p.publicShare.x, 32),
    toBytes(p.publicShare.y, 32),
    toBytes(p.ephemeral.x, 32),
    toBytes(p.ephemeral.y, 32),
    toBytes(p.decryptionShare.x, 32),
    toBytes(p.decryptionShare.y, 32),
    toBytes(p.commitmentA.x, 32),
    toBytes(p.commitmentA.y, 32),
    toBytes(p.commitmentB.x, 32),
    toBytes(p.commitmentB.y, 32),
  );
  return BigInt(keccak256(preimage)) % SUB_ORDER;
}

/**
 * Prove that `decryptionShare = secret * ephemeral` and
 * `publicShare = secret * G`, for the same secret.
 *
 * @param nonce Supply only in deterministic tests. Reusing a nonce across two
 *        proofs with different challenges reveals the secret outright:
 *        subtracting the two responses gives (e1 - e2) * x.
 */
export function proveDleq(params: {
  secret: bigint;
  ephemeral: Point;
  nonce?: bigint;
}): DleqProof {
  const { secret, ephemeral } = params;
  if (secret <= 0n || secret >= SUB_ORDER) {
    throw new Error("proveDleq: the secret must lie in [1, SUB_ORDER)");
  }
  const w = params.nonce ?? randomScalar();
  if (w <= 0n || w >= SUB_ORDER) {
    throw new Error("proveDleq: the nonce must lie in [1, SUB_ORDER)");
  }

  const publicShare = mulBase(secret);
  const share = mulPoint(ephemeral, secret);
  const a = mulBase(w);
  const b = mulPoint(ephemeral, w);
  const e = dleqChallenge({
    publicShare,
    ephemeral,
    decryptionShare: share,
    commitmentA: a,
    commitmentB: b,
  });
  const z = (w + ((e * secret) % SUB_ORDER)) % SUB_ORDER;
  return { a, b, z };
}

/**
 * Verify a Chaum-Pedersen proof:
 *
 *     z*G == A + e*Y_i     and     z*R == B + e*D_i
 *
 * Mirrored on-chain in `OpeningManager`; this implementation exists for the
 * bidder-side and verifier-side tooling and for the cross-language test.
 */
export function verifyDleq(params: {
  publicShare: Point;
  ephemeral: Point;
  decryptionShare: Point;
  proof: DleqProof;
}): boolean {
  const { publicShare, ephemeral, decryptionShare, proof } = params;

  // Reject malformed inputs before doing arithmetic on them, so a proof
  // carrying a non-point cannot be "verified" by accident.
  for (const p of [publicShare, ephemeral, decryptionShare, proof.a, proof.b]) {
    if (!inCurve(p)) return false;
  }
  if (proof.z <= 0n || proof.z >= SUB_ORDER) return false;

  const e = dleqChallenge({
    publicShare,
    ephemeral,
    decryptionShare,
    commitmentA: proof.a,
    commitmentB: proof.b,
  });

  const lhs1 = mulBase(proof.z);
  const rhs1 = addPoint(proof.a, mulPoint(publicShare, e));
  if (!pointsEqual(lhs1, rhs1)) return false;

  const lhs2 = mulPoint(ephemeral, proof.z);
  const rhs2 = addPoint(proof.b, mulPoint(decryptionShare, e));
  return pointsEqual(lhs2, rhs2);
}
