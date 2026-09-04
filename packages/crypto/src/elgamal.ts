/**
 * ElGamal encapsulation of the bid's data-encryption key.
 *
 * Whitepaper Section 6, development plan Section 12.3, encoding spec
 * Section 20.
 *
 * The bidder encrypts its bid under a fresh AES-256 key and encapsulates that
 * key to the tender committee's public key. NO COMMITTEE MEMBER IS INVOLVED AT
 * SUBMISSION TIME - that is the property that makes sealed bidding work
 * without a trusted party holding bids: the bidder needs only a public key
 * that is already frozen on-chain.
 *
 * The committee later recovers the shared secret WITHOUT reconstructing the
 * tender secret. Three members each publish D_i = x_i * R; those interpolate
 * in the exponent to x * R. The tender secret never exists anywhere after the
 * dealing ceremony.
 */
import { keccak256 } from "ethers";
import {
  SUB_ORDER,
  mulBase,
  mulPoint,
  isInPrimeSubgroup,
  type Point,
} from "./babyjub.js";
import { RAW_DEK_V1 } from "./domains.js";
import { concatBytes, toBytes } from "./field.js";
import { randomScalar } from "./vss.js";
import { getBytes } from "ethers";

/** The public half of an encapsulation, carried in the ciphertext. */
export interface Encapsulation {
  /** R = r * G. */
  ephemeral: Point;
  /** dek XOR KDF(S), 32 bytes. */
  wrapped: Uint8Array;
}

/**
 * KDF(S) = keccak256(RAW_DEK_V1 || S.x || S.y). Spec Section 20.
 *
 * BOTH coordinates enter the hash. Using only S.x would make S and -S derive
 * the same key, and those two points are distinguishable to an attacker who
 * gets to choose points.
 */
export function deriveWrappingKey(shared: Point): Uint8Array {
  return getBytes(
    keccak256(
      concatBytes(
        getBytes(RAW_DEK_V1),
        toBytes(shared.x, 32),
        toBytes(shared.y, 32),
      ),
    ),
  );
}

function xor32(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== 32 || b.length !== 32) {
    throw new Error("xor32: both operands must be 32 bytes");
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = a[i] ^ b[i];
  return out;
}

/**
 * Encapsulate `dek` to the tender public key.
 *
 * @param ephemeralScalar Supply only in deterministic tests. Production must
 *        let this be drawn here: two bids sharing `r` under one tender key
 *        share the wrapping key, and the XOR of their `wrapped` values leaks
 *        the XOR of their DEKs.
 */
export function encapsulate(
  tenderPublicKey: Point,
  dek: Uint8Array,
  ephemeralScalar?: bigint,
): Encapsulation & { shared: Point } {
  if (dek.length !== 32) throw new Error("encapsulate: dek must be 32 bytes");

  // A tender key outside the prime-order subgroup would leak information
  // about the plaintext through its small-order component. The contract
  // rejects such a key at activation; checking again here means a bidder
  // running against a misconfigured or hostile front end still refuses.
  if (!isInPrimeSubgroup(tenderPublicKey)) {
    throw new Error(
      "encapsulate: the tender public key is not in the prime-order subgroup - " +
        "refusing to encrypt to it",
    );
  }

  const r = ephemeralScalar ?? randomScalar();
  if (r <= 0n || r >= SUB_ORDER) {
    throw new Error("encapsulate: the ephemeral scalar must lie in [1, SUB_ORDER)");
  }

  const ephemeral = mulBase(r);
  const shared = mulPoint(tenderPublicKey, r);
  return { ephemeral, wrapped: xor32(dek, deriveWrappingKey(shared)), shared };
}

/**
 * Recover `dek` given the shared secret the committee reconstructed.
 *
 * Takes `S` rather than the tender secret, because the opening path never has
 * the tender secret. `combineInExponent` produces `S` from three decryption
 * shares.
 */
export function unwrapDek(wrapped: Uint8Array, shared: Point): Uint8Array {
  if (wrapped.length !== 32) throw new Error("unwrapDek: wrapped must be 32 bytes");
  return xor32(wrapped, deriveWrappingKey(shared));
}

/**
 * One committee member's decryption share for a ciphertext's ephemeral point.
 *
 * D_i = x_i * R. Publishing this is safe: it is a per-tender, per-ciphertext
 * value, not a long-lived secret, and publishing it is what makes the opening
 * ceremony independently verifiable.
 */
export function decryptionShare(memberSecretShare: bigint, ephemeral: Point): Point {
  return mulPoint(ephemeral, memberSecretShare % SUB_ORDER);
}
