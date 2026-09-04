/**
 * BN254 field arithmetic and the encoding rules of docs/field-encoding.md.
 *
 * This module is the ONLY place these rules are implemented in TypeScript.
 * Circuits and contracts must agree with it, enforced by the cross-language
 * equality test (development plan Section 11A.6).
 */

/** BN254 scalar field prime. Spec Section 1. */
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Largest safe unsigned width for an unreduced value: 248 bits (31 bytes).
 * FIELD_PRIME is 254 bits, so any 248-bit value is unambiguously < p.
 */
export const SAFE_BITS = 248n;
export const SAFE_MAX = (1n << SAFE_BITS) - 1n;

/**
 * Truncate a 256-bit digest to a field element by keeping the high 248 bits.
 * Spec Section 2.
 *
 * Right shift, NOT modular reduction. `mod p` would let distinct digests
 * collide in a way an attacker can search, invisibly in the witness.
 */
export function toField(digest: string | Uint8Array | bigint): bigint {
  const value = toBigInt(digest);
  if (value >= 1n << 256n) {
    throw new Error(`toField: value exceeds 256 bits`);
  }
  return value >> 8n;
}

/** Interpret hex string / bytes / bigint as a big-endian unsigned integer. */
export function toBigInt(value: string | Uint8Array | bigint): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "string") {
    const hex = value.startsWith("0x") ? value.slice(2) : value;
    if (hex.length === 0) return 0n;
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      throw new Error(`toBigInt: not a hex string: ${value}`);
    }
    return BigInt("0x" + hex);
  }
  let acc = 0n;
  for (const byte of value) acc = (acc << 8n) | BigInt(byte);
  return acc;
}

/** Split a 32-byte hash into two 128-bit limbs. Spec Section 4. */
export function toLimbs(hash: string | Uint8Array | bigint): {
  hi: bigint;
  lo: bigint;
} {
  const value = toBigInt(hash);
  if (value >= 1n << 256n) {
    throw new Error("toLimbs: value exceeds 256 bits");
  }
  return {
    hi: value >> 128n,
    lo: value & ((1n << 128n) - 1n),
  };
}

/** Reconstruct a 32-byte hash from two 128-bit limbs. Inverse of toLimbs. */
export function fromLimbs(hi: bigint, lo: bigint): string {
  if (hi >= 1n << 128n) throw new Error("fromLimbs: hi limb exceeds 128 bits");
  if (lo >= 1n << 128n) throw new Error("fromLimbs: lo limb exceeds 128 bits");
  return toHex32((hi << 128n) | lo);
}

/** Format a bigint as a 0x-prefixed 32-byte big-endian hex string. */
export function toHex32(value: bigint): string {
  if (value < 0n) throw new Error("toHex32: negative value");
  if (value >= 1n << 256n) throw new Error("toHex32: value exceeds 256 bits");
  return "0x" + value.toString(16).padStart(64, "0");
}

/** Big-endian byte encoding of an unsigned integer at a fixed width. */
export function toBytes(value: bigint, byteLength: number): Uint8Array {
  if (value < 0n) throw new Error("toBytes: negative value");
  const out = new Uint8Array(byteLength);
  let v = value;
  for (let i = byteLength - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    throw new Error(`toBytes: value does not fit in ${byteLength} bytes`);
  }
  return out;
}

/** Concatenate byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Assert a value is a valid field element (< p). */
export function assertField(value: bigint, label: string): bigint {
  if (value < 0n) throw new Error(`${label}: negative field element`);
  if (value >= FIELD_PRIME) {
    throw new Error(`${label}: value >= FIELD_PRIME, not a valid field element`);
  }
  return value;
}

/**
 * Assert a value fits an unsigned integer of the given bit width.
 * Mirrors the Num2Bits range constraints of spec Section 14, so an
 * out-of-range value is caught in TypeScript before it ever reaches a
 * circuit that would reject it far less legibly.
 */
export function assertUint(value: bigint, bits: number, label: string): bigint {
  if (value < 0n) throw new Error(`${label}: negative value`);
  if (value >= 1n << BigInt(bits)) {
    throw new Error(`${label}: exceeds uint${bits}`);
  }
  return value;
}
